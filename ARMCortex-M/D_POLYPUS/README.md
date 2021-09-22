From the paper:

- Within the Bluetooth firmware the ROM starts at 0x0 and the RAM at 0x200000. 
- ROM can be read and executed, while RAM can also be written.
- There is no execution prevention. 
- The ROM of each firmware starts with: 
  ```
  0x000: 00 04 20 00 dcd bootcheck
  0x004: bd 03 00 00 dcd __reset+1
  0x008: 6d 01 00 00 dcd __tx_NMIHandler+1
  0x00c: a1 01 00 00 dcd HardFaultInt+1
  ...
  __tx_NMIHandler
  0x16c: 00 bf nop
  0x16e: 00 bf nop
  0x170: 22 e0 b WDogInt
  ```
- The Reset Vector is always located at offset 0x4. 
- Firmware Reset Vector starts the firmware by initializing hardware components and booting the underlying ThreadX operating system. 
