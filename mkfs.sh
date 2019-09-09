cp /home/br/bsdpad/trunk/commands/de4_beri_iommu/* /home/br/world-mips64/root/

echo "./root/d type=file uname=root gname=wheel mode=0755 size=1000 tags=package=runtime,config" >> /home/br/world-mips64/METALOG
echo "./root/e type=file uname=root gname=wheel mode=0755 size=1000 tags=package=runtime,config" >> /home/br/world-mips64/METALOG
echo "./root/detach.sh type=file uname=root gname=wheel mode=0755 size=1000 tags=package=runtime,config" >> /home/br/world-mips64/METALOG
echo "./root/run.sh type=file uname=root gname=wheel mode=0755 size=1000 tags=package=runtime,config" >> /home/br/world-mips64/METALOG
echo "./root/test.sh type=file uname=root gname=wheel mode=0755 size=1000 tags=package=runtime,config" >> /home/br/world-mips64/METALOG
echo "./etc/rc.conf type=file uname=root gname=wheel mode=0755 size=1000 tags=package=runtime,config" >> /home/br/world-mips64/METALOG
echo "./etc/fstab type=file uname=root gname=wheel mode=0755 size=1000 tags=package=runtime,config" >> /home/br/world-mips64/METALOG

tools/tools/makeroot/makeroot.sh -B big -s 26m -f hwpmc.files mips.img /home/br/world-mips64
