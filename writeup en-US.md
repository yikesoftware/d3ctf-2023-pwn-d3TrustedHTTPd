## d3TrustedHTTPd

> Github Repo：[d3ctf-2022-pwn-d3TrustedHTTPd](https://github.com/yikesoftware/d3ctf-2022-pwn-d3TrustedHTTPd)

> Author：Eqqie @ D^3CTF

### Analysis

This is a challenge about ARM TEE vulnerability exploitation, I wrote an HTTPd as well as an RPC middleware on top of the regular TEE Pwn. The TA provides authentication services for HTTPd and a simple file system based on OP-TEE secure storage. HTTPd is written based on mini_httpd and the RPC middleware is located in `/usr/bin/optee_d3_trusted_core`, and they are related as follows.

![1](https://s2.loli.net/2023/05/03/pMyUuEAeDsN6lm4.png)

To read the log in secure world (TEE) you can add this line to the QEMU args at `run.sh`.

```shell
-serial tcp:localhost:54320 -serial tcp:localhost:54321 \
```

This challenge contains a lot of code and memory corruption based on logic vulnerabilities, so it takes a lot of time to reverse the program. In order to quickly identify the OP-TEE API in TA I recommend you to use [BinaryAI](https://www.binaryai.cn/) online tool to analyze TA binaries, it can greatly reduce unnecessary workload.

![f5da5a5cb1efe21d620a0a63feda4ff](https://s2.loli.net/2023/05/03/sivkw9IR5JoEcUu.png)

### Step 1

The first vulnerability appears in the RPC implementation between HTTPd and `optee_d3_trusted_core`. HTTPd only replaces spaces with null when getting the username parameter and splices the username into the end of the string used for RPC.

![image-20230502220946251](https://s2.loli.net/2023/05/03/bhKWtqHs89E2jUR.png)

![image-20230502221009171](https://s2.loli.net/2023/05/03/dnCHmKecbaWzBfN.png)

`optee_d3_trusted_core` considers that different fields can be separated by spaces or `\t` (%09) when parsing RPC data, so we can inject additional fields into the RPC request via `\t`.

![image-20230502221340781](https://s2.loli.net/2023/05/03/hie4yxg18blR3HP.png)

When an attacker requests to log in to an `eqqie` user using face_id, the similarity between the real face_id vector and the face_id vector sent by the attacker expressed as the inverse of the Euclidean distance can be leaked by injecting `eqqie%09get_similarity`. 

The attacker can traverse each dimension of the face_id vector in a certain step value (such as 0.015) and request the similarity of the current vector from the server to find the value that maximizes the similarity of each dimension. When all 128 dimensions in the vector have completed this calculation, the vector with the highest overall similarity will be obtained, and when the similarity exceeds the threshold of 85% in the TA, the Face ID authentication can be passed, bypassing the login restriction.

### Step 2

In the second step we complete user privilege elevation by combining a TOCTOU race condition vulnerability and a UAF vulnerability in TA to obtain Admin user privileges.

When we use the `/api/man/user/disable` API to disable a user, HTTPd completes this behavior in two steps, the first step is to kick out the corresponding user using `command user kickout` and then add the user to the disable list using `command user disable`. 

![image-20230502223311793](https://s2.loli.net/2023/05/03/mqhalPFJbIgT7jd.png)

TEE is atomic when calling `TEEC_InvokeCommand` in the same session, that is, only when the current Invoke execution is finished the next Invoke can start to execute, so there is no competition within an Invoke. But here, `TEEC_InvokeCommand` is called twice when implementing kickout, so there is a chance of race condition. 

**Kickout** function is implemented by searching the session list for the session object whose record UID is the same as the UID of the user to be deleted, and releasing it.

![image-20230502223709668](https://s2.loli.net/2023/05/03/upUwTymjv56X3Hd.png)

**Disable** function is implemented by moving the user specified by username from the enable user list to the disable user list.

![image-20230502224103696](https://s2.loli.net/2023/05/03/vQrm5nM7NJzChKa.png)

We can use a race condition idea where we first login to the guest user once to make it have a session, and then use two threads to **disable the guest user** and **log in to the guest user** in parallel. There is a certain probability that when the `/api/man/user/disable` interface kicks out the guest user, the attacker gives a new session to the guest user via the `/api/login` interface, and the `/api/man/user/disable` interface moves the guest user into the disabled list. After completing this attack, the attacker holds a session that refers to the disabled user.

Based on this prerequisite we can exploit the existence of a UAF vulnerability in TA when resetting users. (I use the source code to show the location of the vulnerability more clearly)

![image-20230502225611570](https://s2.loli.net/2023/05/03/b72Yx1jKCTJHtFe.png)

When you reset a user, if the user is already disabled, you will enter the logic as shown in the figure. The user's object is first removed from the user list, and if the `set_face_id` parameter is specified at reset time, a memory area is requested to hold the new face_id vector. The TA then recreates a user using `d3_core_add_user_info`. Finally, the TA iterates through all sessions and compares the uid to update the pointer to the user object referenced by the session. But instead of using `session->uid` when comparing UIDs, `session->user_info->uid` is used incorrectly. The object referenced by `session->user_info` has been freed earlier, so a freed chunk of memory is referenced here. If we can occupy this chunk by heap fengshui, we can bypass the updating of the user object reference on this session by modifying the UID hold by `user_info` object and then make the session refer to a fake user object forged by attacker. Naturally, the attacker can make the fake user as an Admin user. 

To complete the attack on this UAF, you can first read this [BGET Explained (phi1010.github.io)](https://phi1010.github.io/2020-09-14-bget-exploitation/) article to understand how the OP-TEE heap allocator works. The OP-TEE heap allocator is roughly similar to the unsorted bin in Glibc, except that the bin starts with a large freed chunk, which is split from the tail of the larger chunk when allocating through the bin. When releasing the chunk, it tries to merge the freed chunk before and after and insert it into the bin via a FIFO strategy. In order to exploit this vulnerability, we need to call the reset function after we adjust the heap layout from A to B, and then we can use the `delete->create->create` gadget in reset function. It will make the heap layout change in the way of C->D->E. In the end we can forge a Admin user by controlling the new face data.

![image-20230502232518449](https://s2.loli.net/2023/05/03/p8WsyVN4JtRfq5K.png)

### Step 3

When we can get Admin privileges, we can fully use the secure file system implemented in TA based on OP-TEE secure storage (only read-only privileges for normal users). 

The secure file system has two modes of **erase** and **mark** when deleting files or directories. The erase mode will delete the entire file object from the OP-TEE secure storage, while the mark mode is marked as deleted in the file node, and the node will not be reused until there is no free slot.

The secure file system uses the `SecFile` data structure when storing files and directories. When creating a directory, the status is set to `0xffff1001` (for a file, this value is `0xffff0000`). There are two options for deleting a directory, **recursive** and **non-recursive**. When deleting a directory in recursive mode, the data in the secure storage will not be erased, but marked as deleted.

```c
typedef struct SecFile sec_file_t;
typedef sec_file_t sec_dir_t;
#pragma pack(push, 4)
struct SecFile{
	uint32_t magic;
	char hash[TEE_SHA256_HASH_SIZE];
	uint32_t name_size;
	uint32_t data_size;
	char filename[MAX_FILE_NAME];
	uint32_t status;
	char data[0];
};
#pragma pack(pop)
```

There is a small bug when creating files with `d3_core_create_secure_file` that the `status` field is not rewritten when reusing a slot that is marked as deleted (compared to `d3_core_create_secure_dir` which does not have this flaw). This does not directly affect much. 

![image-20230503003858564](https://s2.loli.net/2023/05/03/faoiIJ67QUPg95X.png)

![image-20230503003654968](https://s2.loli.net/2023/05/03/8pXANtxW1OoQLPd.png)

But there is another flaw when renaming files, that is, it is allowed to set a file name with a length of 128 bytes. Since the maximum length of the file name field is 128, this flaw will cause the filename to loss the null byte at the end. This vulnerability combined with the flaw of rewriting of the `status` field will include the length of the file name itself and the length of the file content when updating the length of the file name. This causes the file name and content of the file to be brought together when using `d3_core_get_sec_file_info` to read file information.

![7ac17a0ea058ffb702e9754be596f8d](https://s2.loli.net/2023/05/03/SZwUrxIDz9n7Kji.png)

![070b86d520221b246afa7a1b2598b79](https://s2.loli.net/2023/05/03/fnVMyxIpuTtvwAg.png)

When the `d3_core_get_sec_file_info` function is called, the pointer to store the file information in the CA will be passed to the TA in the way of `TEEC_MEMREF_TEMP_INPUT`. This pointer references the CA's buffer on the stack.

![image-20230503004650985](https://s2.loli.net/2023/05/03/y7AS58Qx3Mq1EiI.png)

![12c883cc1a6d7728775b01700b41b2f](https://s2.loli.net/2023/05/03/ev7FwSyLDkNKQ1U.png)

![617a2c40f860058a6151024fff90ab7](https://s2.loli.net/2023/05/03/3muXdLSOQcRKB4r.png)

![image-20230503011850677](https://s2.loli.net/2023/05/03/WPa7jyZzUnmk81L.png)

The `TEEC_MEMREF_TEMP_INPUT` type parameter of CA is not copied but mapped when passed to TA. This mapping is usually mapped in a **page-aligned** manner, which means that it is not only the data of the size specified in `tmpref.size` that is mapped to the TA address space, but also other data that is located in the same page. As shown in the figure, it represents the address space of a TA, and the marked position is the buffer parameter mapped into the TA.

![image-20230503005412695](https://s2.loli.net/2023/05/03/Uil428yKJpbHnQx.png)

In this challenge, the extra data we write to the buffer using `d3_core_get_sec_file_info` will cause a **stack overflow** in the CA, because the buffer for storing the file name in the CA is only 128 bytes, as long as the file content is large enough, we can overwrite it to the return address in the CA. Since the `optee_d3_trusted_core` process works with **root privileges**, hijacking its control flow can find a way to obtain the content of `/flag.txt` with the permission flag of `400`. Note that during buffer overflow, `/api/secfs/file/update` can be used to pre-occupy a larger filename size, thereby bypassing the limitation that the content after the null byte cannot be copied to the buffer.

With the help of the statically compiled `gdbserver`, we can quickly determine the stack location that can control the return address. For functions with buffer variables, aarch64 will put the return address on the top of the stack to prevent it from being overwritten. What we overwrite is actually the return address of the upper-level function. With the help of the **almighty gadget** in aarch64 ELF, we can control the `chmod` function to set the permission of `/flag.txt` to `766`, and then read the flag content directly from HTTPd.

![image-20230503011343736](https://s2.loli.net/2023/05/03/CchYHOqt46T3IGB.png)

![image-20230503011458586](https://s2.loli.net/2023/05/03/3D5JnBAPIoC8ptU.png)

### Exploit

See code in [exp.py](https://github.com/yikesoftware/d3ctf-2022-pwn-d3TrustedHTTPd/blob/main/exp.py)

