#!/bin/sh

# mksquashfs and unsquashfs and copy them
cd tools
cd squashfs-tools
make
cd ..
cd ..

cp ./tools/squashfs-tools/mksquashfs         ./firmware/tools/mksquashfs -f
cp ./tools/squashfs-tools/unsquashfs         ./firmware/tools/unsquashfs -f

# copy Sercomm's lib
cp ./firmware/sercomm_lib/nvram              ./firmware/apps -f -R
cp ./firmware/sercomm_lib/shared             ./firmware/apps -f -R
cp ./firmware/sercomm_lib/wsc                ./firmware/apps -f -R
cp ./firmware/sercomm_lib/wsc_module         ./firmware/apps -f -R

cp ./tools/mips_tools.clean.tar.gz            /opt/mips_tools.clean.tar.gz -f -R

cd /opt
tar -xzvf  mips_tools.clean.tar.gz
cd -

#build toolchain
cd ./bootloader/
tar -xzvf ip1006aa_redboot_GPL_v102.tgz
cp -f ./ecosconfig_tools.tgz   ./ip1006aa_redboot_GPL_v102/ecosconfig_tools.tgz
cp -f ./mips-tools.tgz         ./ip1006aa_redboot_GPL_v102/mips-tools.tgz
cd ./ip1006aa_redboot_GPL_v102
tar -xzvf  ecosconfig_tools.tgz
tar -xzvf  mips-tools.tgz
make pb42_rom
cd ../..
cp -f ./bootloader/ip1006aa_redboot_GPL_v102/rom_bld/install/bin/redboot.rom   ./firmware/binfile/redboot.rom

#build fw
cd ./firmware
./prepare_compile.sh binary-toolchain
./build.sh

echo "*********************** COMPLETED ************************"
