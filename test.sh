#!/usr/bin/bash


CWD=$(cd $(dirname $0);pwd)


dir_in="$1"
dir_test="$(mktemp -d --suffix .tar-test)"

dir_out="$dir_test/out"

if [ ! -d "$dir_in" ];then
    echo "输入目录必须存在..."
    exit 1
fi

if [ ! -d "$dir_test" ];then
    echo "输出目录必须存在..."
    exit 1
fi

if [ ! -d "$dir_out" ];then
    mkdir -v "$dir_out"
fi

if [ -x dist/tarpy ];then
    CMD="dist/tarpy"
else
    CMD="python ${CWD}/src/tar.py"
fi

test_tar=$(mktemp -u -p "$dir_test" --suffix .tar)
echo "创建: $test_tar"
$CMD -vcf "$test_tar" "$dir_in" && echo "测试创建*.tar 成功"
$CMD -vxf "$test_tar" -C "$dir_out" && echo "测试解压*.tar 成功"
rm -rf "$dir_out"
mkdir "$dir_out"


test_tar=$(mktemp -u -p "$dir_test" --suffix .tar.zst)
echo "创建: $test_tar"
$CMD -zvcf "$test_tar" "$dir_in" && echo "测试创建*.tar.zst 成功"
$CMD -zvxf "$test_tar" -C "$dir_out" && echo "测试解压*.tar.zst 成功"
rm -rf "$dir_out/"
mkdir "$dir_out"

test_tar=$(mktemp -u -p "$dir_test" --suffix .tar.zst.aes)
echo "创建: $test_tar"
$CMD -k "123456" -ezvcf "$test_tar" "$dir_in" && echo "测试创建*.tar.zst.aes 成功"
$CMD -k "123456" -ezvxf "$test_tar" -C "$dir_out" && echo "测试解压*.tar.zst.aes 成功"
rm -rf "$dir_out/"
mkdir "$dir_out"



# 测试从标准输入和标准输出
test_tar=$(mktemp -u -p "$dir_test" --suffix .tar.zst.aes)
echo "创建: $test_tar"
$CMD -k "123456" -ezvc "$dir_in" > "$test_tar" && echo "测试 从标准输出 创建*.tar.zst.aes 成功"
cat "$test_tar" | $CMD -k "123456" -ezx -C "$dir_out" && echo "测试 从标准输入 解压*.tar.zst.aes 成功"
rm -rf "$dir_out/"
mkdir "$dir_out"


# 测试解压 *.tar.gz *.tar.bz2 *.tar.xz
test_tar=$(mktemp -u -p "$dir_test" --suffix .tar.gz)
echo "创建: $test_tar"
tar -zvcf "$test_tar" "$dir_in" && echo "tar 工具 创建*.tar.gz"
echo "解压：*.tar.gz"
$CMD -vxf "$test_tar" -C "$dir_out"
rm -rf "$dir_out/"
mkdir "$dir_out"

echo "从标准输入解压：*.tar.gz"
cat "$test_tar" | $CMD -vx -C "$dir_out" && echo "测试 从标准输入 解压*.tar.gz 成功"
rm -rf "$dir_out/"
mkdir "$dir_out"

# python ${CWD}/src/tar.py -k "123456" -eztvf "$test_tar" && echo "测试从 *.tar.zst.aes 查看成功"
echo "测试完成，可以删除目录: $dir_test"

