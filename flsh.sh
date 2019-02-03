esptool.py --chip esp32 --port /dev/ttyUSB0 --baud 921600 write_flash 0x1000 bootloader.bin 0x8000 partitions.bin 0x10000 nuttx.bin
