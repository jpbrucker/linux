#!/bin/sh
# Regression tests for SMMU test engine
# Note: we don't handle failures very well. Some might get lost in pipes.
# Failures should be visible in dmesg, though. Also grep for "Segfault"

#set -e
S="smmute -c"
DEV=smmute
LOGS=/smmute-$(date -Is).log

# I run the model with "bp.mmc.p_mmc_file=.../mmc_disk.bin"
# This is used for testing file-backed mmap
BLKDEV=/dev/mmcblk0p1
MNTPOINT=/mnt/
# IN_FILE must exist and must be quite big (I use 1G)
IN_FILE=${MNTPOINT}random.dat
OUT_FILE=${MNTPOINT}out.dat

TMP_API_DETECT=/tmp/smmute-api-detect.log
smmute 2>/dev/null >$TMP_API_DETECT
RET=$?

# Old version of smmute used to output everything in stderr in order to keep
# stdin/stdout for splice. splice is now dead.
if [ $RET -eq 0 ] && ! [ -s $TMP_API_DETECT ]; then
    _smmute () {
        $S $@ 2>&1 >/dev/null
    }
else
    # If basic 'smmute' command failed, tests will fail anyway so API version
    # doesn't matter
    _smmute () {
        $S $@
    }
fi

rm -f $TMP_API_DETECT

echoe () {
    echo $@ >&2
}

default_dev () {
    if $vfio; then
        get_vfio_ipc 0
    else
        find /dev/ -name "smmute*" -maxdepth 1 | sort | head -n 1
    fi
}

ss () {
    name="$S -s $size $@"
    echoe "### TEST $name ###"
    _smmute -s $size $@ || fail "$name"
}

fail () {
    echoe "FAIL '$@'"
}

get_random () {
    # Get a random multiple of $align in [$base; $base + $limit[
    limit="$1"
    base="$2"
    align="$3"

    # Defaults:
    [ -z "$limit" ] && limit=0x100000
    [ -z "$base" ] && base=0
    [ -z "$align" ] && align=0

    # hex->dec conversion
    base=$(( $base ))
    align=$(( $align ))
    limit=$(( $limit ))

    if [ $base -lt $align ]; then
        base=$align
    fi

    res=$(( $base + $RANDOM % $limit ))

    if [ $align -gt 0 ]; then
        res=$(( $res / $align * $align ))
        if [ $res -lt $base ]; then
            res=$(( $res + $align ))
        fi
    fi

    echo $res
}

has_sva () {
    smmute -h 2>&1 | grep -q -- -u
}

has_file_map () {
    smmute -h 2>&1 | grep -q -- in_file
}

# Check that we handle failures properly
test_failure () {
    # SUM ranges must be aligned on 64-bit. This command should thus fail.
    size=6
    if ! ss $defdev -ms -o 3 2>&1 >/dev/null | grep -q FAIL; then
        echo "Unable to detect failure. Aborting."
        exit 1
    fi
}

# Simple test: one MEMCPY, one RAND, one SUM
test_single () {
    size=$1
    offset=$2
    shift 2

    ss $defdev -o $offset       $@
    ss $defdev -o $offset -mr   $@
    ss $defdev -o $offset -ms   $@
}

cmp_value () {
    tests=$(( $tests + 1 ))
    grep -qi "$1" || fail
}

# Check for regressions in the output format or their values
test_values () {
    echoe "### TEST MEMCPY start... ###"
    _smmute $defdev -s 0x10000 |\
        cmp_value "00000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f"
    echoe "### TEST MEMCPY end... ###"
    _smmute $defdev -s 0x10000 |\
        cmp_value "0fff0: f0 f1 f2 f3 f4 f5 f6 f7 f8 f9 fa fb fc fd fe ff"

    echoe "### TEST SUM on size 0x1000 ###"
    _smmute $defdev -s 0x1000 -ms |\
        cmp_value "value.*= 0x200"

    echoe "### TEST SUM on size 0x58538 ###"
    _smmute $defdev -s 0x58538 -ms |\
        cmp_value "value.*= 0xb0a7"

    if $test_p2p; then
        # First quadword in hex format of the random generator
        local quad=ea0b48ba69d00a6e

        echoe "### TEST P2P ###"
        # Execute a MEMCPY that executes a RAND with seed 0 on the input buffer
        _smmute $defdev -mp | cmp_value "Command is now 0x$quad"
    fi
}

test_p2p () {
    size=0x10000 # doesn't matter
    ss -mp
}

test_parallel () {
    size=$1
    for i in $(seq 5); do
        ss $defdev &
    done
    wait

    if ! $fast; then
        for i in $(seq 64); do
            size=$(get_random 0x100000 $1 8)
            offset=$(get_random 0x10000 0 8)
            dev=$(get_random 4)
            nm=$(get_random 3)
            case $nm in
            0) m=-ms ;;
            1) m=-mm ;;
            2) m=-mr ;;
            esac
            if $vfio; then
                dev_path=$(get_vfio_ipc $dev)
            else
                dev_path=/dev/${DEV}$dev
            fi
            ss $dev_path -o $offset $m &
        done
        wait
    fi
}

files_mounted=false

setup_files () {
    $files_mounted && return 0

    mount $BLKDEV $MNTPOINT || return 1
    files_mounted=true

    return 0
}

teardown_files () {
    ! $files_mounted && return

    umount $BLKDEV
    files_mounted=false
}

__test_multi () {
    local children=$1
    local transactions=$2
    local size=$3
    shift 3

    local name="smmute-multi -f $children -n $transactions -s $size $@"
    echoe "### TEST $name ###"
    smmute-multi -f $children -n $transactions -s $size $@ || fail "$name"
}

test_multi () {
    local dev
    local devs=
    for i in $(seq 0 4); do
        if $vfio; then
            dev="$(get_vfio_ipc $i)"
        else
            dev="/dev/${DEV}$i"
        fi
        [ -e $dev ] && devs="$devs $dev"
    done

    __test_multi 16 16 0x5678 $devs
    __test_multi 64 2 0x2345 $devs
#    __test_multi 128 1 0x1000 -k $devs
}

__test_bind () {
    local mode="$1"
    shift
    local name="smmute-bind -m$mode $@"
    echoe "### TEST $name ###"
    smmute-bind -m "$mode" $@ || fail "$name"
}

test_bind() {
    # Perform lots of bind/unbind calls in parallel
    $vfio && return

    for i in $(seq 0 4); do
        __test_bind bind "/dev/${DEV}$i"
        __test_bind unbind "/dev/${DEV}$i"
    done
}

test_sva () {
    local file_flags

    if ! has_sva; then
        echo "I'm afraid I can't do that."
        exit
    fi

    if has_file_map; then
        file_flags="mmap,in_file=$IN_FILE,out_file=$OUT_FILE"
        file_flags="$file_flags mmap,in_file=$IN_FILE"
        file_flags="$file_flags mmap,out_file=$OUT_FILE"
    fi

    echo "Testing bind/unbind"
    test_bind >> $LOGS 2>&1

    echo "Testing smmute-multi"
    test_multi >> $LOGS 2>&1

    for arg in mmap malloc stack mmap,lock $file_flags; do
        local args="--no-p2p --log-file $LOGS -u$arg"
        $vfio && args="$args --vfio"

        echo "Testing with '$arg'"
        if [ x"$arg" = xstack ]; then
            # TODO: find out why big stack allocations end up in segfault
            args="$args -f"
        fi

        if echo -- "$arg" | grep -q out_file; then
            # Can't let multiple processes truncate and mmap the same file in
            # parallel.
            args="$args --no-parallel"

            ! setup_files && continue
        fi

        if echo -- "$arg" | grep -q in_file; then
            # At the moment we don't check if output values are the same as the
            # input file ones
            args="$args --no-values"

            ! setup_files && continue
        fi

        $0 $args

        # Umounting between tests, instead of doing a single mount for all
        # tests, has the added benefit of clearing the page cache
        teardown_files
    done
}

VFIO_SERVERS=/tmp/vfio-servers.run

launch_vfio_server () {
    # Launch a server for given device, add it to the database
    dev_nr=$1
    smmuted /sys/bus/pci/devices/0000:00:0$(( $dev_nr + 3 )).0/ &
    serv_pid=$!
    is_running=$(ps | grep $serv_pid | grep -v grep)
    if [ -z "$is_running" ]; then
        return 1
    fi

    ipc_path=/tmp/smmute-ipc-$serv_pid.sock

    echo "$dev_nr $serv_pid $ipc_path" >> $VFIO_SERVERS

    return 0
}

get_vfio_ipc () {
    # Get IPC address for VFIO server attached to given device
    dev_nr=$1

    grep "^$dev_nr " $VFIO_SERVERS | cut -d' ' -f 3
}

stop_vfio_servers () {
    cat $VFIO_SERVERS | while read dev_nr serv_pid ipc_path; do
        kill -SIGINT $serv_pid
        wait $serv_pid
    done

    rm $VFIO_SERVERS
}

test_vfio () {
    local BDFs="00:03.0 00:04.0 00:05.0 00:06.0"
    setup_vfio $BDFs || exit 1

    sysfs_devs=
    for bdf in $BDFs; do
        sysfs_devs="$sysfs_devs /sys/bus/pci/devices/0000:$bdf/"
    done

    # First, try without IPC. 
    __test_multi 16 16 0x2930 $sysfs_devs >> $LOGS 2>&1

    # This is great for exercising domains-mm links
    test-vfio-replay

    echo -n > $VFIO_SERVERS || exit 1
    for dev in $(seq 0 3); do
        launch_vfio_server $dev
        if [ $? -ne 0 ]; then
            stop_vfio_servers
            exit 1
        fi
    done

    # Give the servers some time to initialize
    sleep 20

    # This one reproduces a use-after-free situation where the IOMMU driver
    # would call mm_context_put on a reallocated mm.
    vfio=true
    dev=$(default_dev)
    for i in $(seq 256); do
        smmute -bi -q -ummap $dev &
    done

    test_smmute --vfio --log-file "$LOGS" -t sva
    test_smmute --vfio --log-file "$LOGS" --no-p2p --no-values

    stop_vfio_servers

    setup_vfio -r $BDFs || exit 1
}

test_mdev () {
    uuids="49e80872-b905-435c-a563-afa6b313fa86
           ea6c71ef-e8b6-4dfa-96cc-4b42efc7e1fe
           cf87f63a-3bec-4c91-9dc8-06fe0560d3f1
           d8341ecb-b51c-44a3-8fbc-0a68a7d1993f"
    for uuid in $uuids; do
        if [ ! -f /sys/bus/mdev/devices/$uuid ]; then
            echo $uuid > /sys/bus/pci/devices/0000\:00\:03.0/mdev_supported_types/smmute-pci-platform/create
        fi
    done
    sleep 1
    for uuid in $uuids; do
        (
            dev=/sys/bus/mdev/devices/$uuid
            args="-q -bm $dev -s 0x123458"
            ss $args
            ss $args -mr
            ss $args -ms
        ) &
    done
}

test_huge () {
    PGSIZE=$(grep -m1 PageSize /proc/1/smaps | awk '{ print $2 }')
    if [ "$PGSIZE" = 64 ]; then
        nr_hugepages=1
    elif [ "$PGSIZE" = 16 ]; then
        nr_hugepages=2
    else
        nr_hugepages=4
    fi

    smmute-huge -t 1 || return
    smmute-huge -t 2 || return
    smmute-huge -t 3 || return
    smmute-huge -t 4 -n $nr_hugepages || return
    smmute-huge -t 5 -n $nr_hugepages || return
    smmute-huge -t 6 -n $nr_hugepages || return
}

fast=false
size=0x10000
offset=0
test_p2p=true
test_parallel=true
test_values=true
vfio=false
verbose=false

while [ $# -ge 1 ]; do
    case $1 in
        -f)
            # Fast: avoid long-running tests
            fast=true
            ;;
        -t)
            # Execute a single test function. Can be any function defined in
            # this file starting with test_.
            mode="test_$2"
            shift
            ;;
        -s)
            # For single-test mode: set size
            size="$2"
            shift
            ;;
        -o)
            # For single-test mode: set offset (maybe unused)
            offset="$2"
            shift
            ;;
        --no-p2p)
            # Don't test p2p
            test_p2p=false
            ;;
        --no-parallel)
            # Don't run parallel tests
            test_parallel=false
            ;;
        --no-values)
            test_values=false
            ;;
        --log-file)
            LOGS="$2"
            shift
            ;;
        --vfio)
            # Use devices through VFIO instead of normal driver. This is
            # internal, as it requires test_vfio to launch the VFIO servers.
            vfio=true
            S="$S -bi"
            ;;
        -v)
            verbose=true
            ;;
        -h)
            echo -e "Unknown parameter $1\n"
            echo "Usage: $0 [-v] [-t <test name> [-s <size>] [-o <off>]] [smmute args]"
            exit 1
            ;;

        *)
            # Anything else is added to the smmute command
            S="$S $1"
            ;;
    esac
    shift
done

defdev=$(default_dev)

echo "Logging to $LOGS"

if [ -n "$mode" ]; then
    $mode $size $offset
    exit
fi

$verbose && set -x

test_failure

test_single 0x1000 0 >>$LOGS 2>&1
test_single 0x1000 0 >>$LOGS 2>&1

for s in 0x1000 0x10000 0x20000; do
    for o in 0 8 16 32 64 128 2048; do
        test_single $s $o >>$LOGS 2>&1
    done
done

if ! $fast; then
    s=0x8a9108
    for o in 0 8 16 32 64 128 2048 49248; do
        test_single $s $o >>$LOGS 2>&1
    done

    for i in $(seq 12); do
        s=$(get_random 0x10000 8 8)
        o=$(get_random 0x10000 0 8)
        test_single $s $o -n 3 -r 3 >>$LOGS 2>&1
    done

    # 256M (removed, takes too long.)
    #test_single 0x10000000 0 >>$LOGS 2>&1
fi

if $test_values; then
    test_values >>$LOGS 2>&1
fi

if $test_p2p; then
    test_p2p >>$LOGS 2>&1
fi

if $test_parallel; then
    for s in 0x1000 0x10000 0x4; do
        test_parallel $s >>$LOGS 2>&1
    done
fi

tests=$(grep "TEST" $LOGS | wc -l)
failures=$(grep "FAIL\|Segmentation fault" $LOGS | wc -l)
if [ $failures -ne 0 ]; then
    echo "$failures FAIL / $tests TESTS"
    exit 1
else
    echo "$tests SUCCESS"
fi
