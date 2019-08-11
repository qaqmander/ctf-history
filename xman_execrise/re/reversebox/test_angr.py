#!/usr/bin/env python3
import angr, claripy

proj = angr.Project('./reverse_box')

@proj.hook(0x080485B1)
def my_hook(state):
    state.regs.eax=0xd6

arg1 = claripy.BVS('arg1', 8)

initial_state = proj.factory.entry_state(args=['./reverse_box', arg1])

sm = proj.factory.simgr(initial_state)

#sm.explore(find=0x08048712, avoid=0x0804875F)
#sm.explore(find=0x08048687)
sm.explore(find=0x08048712)
state = sm.found[0]

target = [149, 238, 175, 149, 239, 148, 35, 73, 153, 88, 47, 114, 47, 73, 47, 114, 177, 154, 122, 175, 114, 230, 231, 118, 181, 122, 238, 114, 47, 231, 122, 181, 173, 154, 174, 177, 86, 114, 150, 118, 174, 122, 35, 109, 153, 177, 223, 74]

ans = []
for i in target:
    ans.append(state.solver.eval(arg1, extra_constraints=(state.regs.eax==i,)))
print(''.join(map(chr, ans)))

#import IPython
#IPython.embed()
