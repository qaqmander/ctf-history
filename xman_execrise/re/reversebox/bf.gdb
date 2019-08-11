set $i = 0
b *0x080485BD
b *0x8048712

while ($i < 256)
    p $i
    set $i = $i + 1
    run T
    set $eax = $i
    c
    p *(char *)0xffffd4b4
    if (*(char *)0xffffd4b4 == (char)0x95)
        echo success!\n
        p $i
        loop_break
    end
end
