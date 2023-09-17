##  The script routine is for user to choose compile mode##

# parameter check
if [ $# -ne 1 ]
then
	echo Usage: ./prepare compile-mode
	echo compile-mode: binary-toolchain source-toolchain
	echo binary-toolchain: means using factory toolchain binary to build f5d8232-4.
	echo source-toolchain: means using attached toolchain source code to build f5d8232-4.
	echo Please backup your file under /home/toolchain to other dir,if you choose source-toolchain
	exit 0
fi

# remove the previous project.mk
if [ -f project.mk ]
then
	rm project.mk
fi


# set compile variable
if [ $1 = binary-toolchain ]
then
	echo "export TOOL_CHAIN_MODE = binary" >> project.mk
elif [ $1 = source-toolchain ]
then
	echo "toolchain source is not available yet"
#	rm /home/toolchain -f -R
#	mkdir /home/toolchain
#	cp ./toolchain-source-code/build_toolchain.sh                  /home/toolchain/build_toolchain.sh
#	cp ./toolchain-source-code/uclibc-crosstools-3.4.2-12.src.rpm  /home/toolchain/uclibc-crosstools-3.4.2-12.src.rpm
#	cd /home/toolchain
#	echo "export TOOL_CHAIN_MODE = source " >> project.mk
#	./build_toolchain.sh
else
	echo "compile-mode error"
fi
