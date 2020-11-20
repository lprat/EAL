#!/bin/sh
#Package Artefacts Extract Linux
#docker build -t package_eal .
#docker run --rm -v $(pwd)/output:/tmp/output -ti package_eal
if [ ! -x "$(which wget)" ] ; then
    echo "Could not find wget, please install." >&2
fi
if [ ! -x "$(which curl)" ]; then
    echo "Could not find curl, please install." >&2
fi
if [ ! -x "$(which unzip)" ]; then
    echo "Could not find unzip, please install." >&2
fi
if [ ! -x "$(which git)" ]; then
    echo "Could not find git, please install." >&2
fi
if [ ! -x "$(which openssl)" ]; then
    echo "Could not find openssl, please install." >&2
fi
if [ ! -x "$(which tar)" ]; then
    echo "Could not find tar, please install." >&2
fi
if [ ! -x "$(which gzip)" ]; then
    echo "Could not find gzip, please install." >&2
fi
#Menu from https://bioinfo-fr.net/astuce-ajouter-des-options-dans-un-script-bash-avec-getopt
#Options from https://stackoverflow.com/questions/14513305/how-to-write-unix-shell-scripts-with-options
PUBKEY_PATH=""
PUBKEY_URL=""
YARA_URL=""
YARA_URLGIT=""
YARA_PATH=""
YARA_BASE=1
options="$@"

function usage(){
	printf "Use script to make package EAL :\n"
	printf "\t-p                : path of pub key for encrypt archive ;\n"
	printf "\t-w               : url of pub key for encrypt archive ;\n"
	printf "\t-u                : url to download yara rules for linux ;\n"
	printf "\t-g                : url git to download yara rules for linux ;\n"
	printf "\t-y                : path contains yara rules for linux ;\n"
	printf "\t-c                : dont use community yara rules for linux ;\n"
	printf "\t-h                : help.\n"
	exit 0
}

set_options(){
    prev_option=""

    for option in $options;
    do
        case $prev_option in
            "-p" )
                PUBKEY_PATH=$option
            ;;
            "-u" )
                YARA_URL=$option
            ;;
            "-g" )
                YARA_URLGIT=$option
            ;;
            "-y" )
                YARA_PATH=$option
            ;;
            "-w" )
                PUBKEY_URL=$option
            ;;

        esac

        prev_option="$option"

    done

}

if [ $# -ne 0 ]
then
    if [[ $options == *"-h"* ]]; then usage ;fi
     if [[ $options == *"-c"* ]]; then YARA_BASE=0 ;fi
	set_options
fi

cd /tmp

## get EAL
git clone https://github.com/lprat/EAL
cp EAL/extract-artefacts.sh .
if [ $YARA_BASE == 1 ]
then
  mv EAL/yara_rules ./yararules
fi
rm -rf EAL

## change dir
rm -rf tools
mkdir tools
cd tools/

## Download avml to try extract memory (https://github.com/microsoft/avml)
curl -s https://api.github.com/repos/microsoft/avml/releases/latest \
| grep "avml-minimal" \
| cut -d : -f 2,3 \
| tr -d \" \
| wget -qi -

## Download spyre to check Yara rules
git clone https://github.com/spyre-project/spyre && cd spyre && make && make release && cd ../
cp spyre/_build/x86_64-linux-musl/spyre spyre_x64
cp spyre/_build/i386-linux-musl/spyre spyre_x86
rm -rf spyre/

## Download yara Linux Yara rules
#community rules (find new: https://github.com/InQuest/awesome-yara)
if [[ $YARA_URL == "http"* ]]; then
  wget $YARA_URL -O yararules/custom.yar
fi
if [[ $YARA_URLGIT == "http"* ]]; then
  git clone $YARA_URLGIT yararules/yaragit
  #cp yara rules in parent dir
  cd yararules
  find yaragit/ -iname '*.yar*'  -exec cp {} ./ \;
  rm -rf yaragit
  cd ../
fi
if [ -d "$YARA_PATH" ]; then
  #get file
  cp -r $YARA_PATH yararules/yarapath
  #cp yara rules in parent dir
  cd yararules
  find yarapath/ -iname '*.yar*'  -exec cp {} ./ \;
  rm -rf yarapath/
  cd ../
fi
if [ -f "$YARA_PATH" ]; then
  #get file
  cp $YARA_PATH yararules/
fi
#check yararules with yarac
python3 /opt/merge_yararules.py yararules/fs/
mv merged.yara filescan.yar
python3 /opt/merge_yararules.py yararules/mem/
mv merged.yara procscan.yar
rm -rf yararules/

## Download or apply public certificate to encrypt archive file
if [[ $PUBKEY_URL == "http"* ]]; then
#download
wget $PUBKEY_URL -O pub_key
fi
if [ -f "$PUBKEY_PATH" ]; then
#get file
cp $PUBKEY_PATH ./pub_key
fi
if [ -f "pub_key" ]; then
#verify key
   echo "Verify PUB_KEY..."
  openssl pkey -inform PEM -pubin -in pub_key -noout &> /dev/null
  if [ $? != 0 ] ; then
    echo "this was definitely not a public key in PEM format"
    cd ../
    rm -rf tools/
    exit 1
  fi
  echo "OK"
fi

## Download debian security tracker data
wget https://security-tracker.debian.org/tracker/debsecan/release/1/GENERIC -O GENERIC
## make script extrat
cd ../
tar czvf tools.tar.gz tools/
openssl base64 < tools.tar.gz > tools.b64
rm -rf tools
rm tools.tar.gz
sed  -i '1i cat << EOF > /tmp/toolsEAL/tools.tar.gz' tools.b64
echo 'EOF' >> tools.b64
echo 'tar -C  /tmp/toolsEAL/ -zxf /tmp/toolsEAL/tools.tar.gz' >> tools.b64
sed  -i '1i mkdir /tmp/toolsEAL' tools.b64
sed  -i '1i rm -rf /tmp/toolsEAL' tools.b64
sed -i -e '/#ATTACH_TOOLS/{r tools.b64' -e 'd}' extract-artefacts.sh
rm tools.b64
cp extract-artefacts.sh /tmp/output/extract-artefacts.sh
echo "copy script extract-artefacts.sh on linux where you want extract artefacts!"
