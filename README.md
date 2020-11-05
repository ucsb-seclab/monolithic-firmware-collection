# monolithic-firmware-collection

Collecting monolithic firmware images for research is well-known to be a tedious and time-consuming process.
The creation of these dataset usually requires getting in contact with multiple people hoping for a private data-sharing, buying random IoT stuff and hoping both to not destroy the
device and that the dumped firmware is not Linux based, or finally going through the state of the art papers and navigate multiple repositories in the hope of finding something useful. 

With this repo, we want to create a centralize spot where researchers can share their firmware blob with some metadata attached to help everybody.
No more papers with 3 examples, less time wasted looking for those, less money spent to dump another firmware already dumped by somebody else.

Share your blob! 




# Contributors

Here all the papers from where this dataset has been created.

| Paper Name  | Link 
|---------|------------------|
| Toward the Analysis of Embedded Firmware through Automated Re-hosting | https://www.usenix.org/system/files/raid2019-gustafson.pdf      |
| HALucinator: Firmware Re-hosting Through Abstraction Layer Emulation |      https://www.usenix.org/system/files/sec20summer_clements_prepub.pdf      |
| P2IM: Scalable and Hardware-independent Firmware Testing via Automatic Peripheral Interface Modeling  |      https://www.usenix.org/system/files/sec20spring_feng_prepub_0.pdf      |       
| What You Corrupt Is Not What You Crash: Challenges in Fuzzing Embedded Devices | http://s3.eurecom.fr/docs/ndss18_muench.pdf |
| BootStomp: On the Security of Bootloaders in Mobile Devices | https://www.usenix.org/system/files/conference/usenixsecurity17/sec17-redini.pdf |

Here a list of other sources from which these blobs are coming from:

* https://github.com/TrustworthyComputing/csaw_esc_2019
* https://os.mbed.com/platforms/FRDM-K64F/
* https://github.com/grant-h/ShannonBaseband/tree/master/firmware
* You?
