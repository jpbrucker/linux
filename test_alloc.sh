#!/bin/sh -e

CHUNK_HDR_SIZE=32
CHUNK_MIN_ALLOC=8

ALLOCATOR_START=0x400008000000 # Hex addr
ALLOCATOR_SIZE=134217728

SSH="ssh root@127.0.0.1 -p 2222"
DEBUGFS="/sys/kernel/debug/"
BC=$(which bc)

calc()
{
    echo "$@" | $BC
}

dec_to_hex()
{
    printf "%x\n" $1
}

hex_to_dec()
{
    printf "%d\n" $1
}

alloc()
{
    $SSH "echo $1 > $DEBUGFS/hyp_alloc"
}

free()
{
    local addr=$(calc $(hex_to_dec $ALLOCATOR_START)+$1)

    $SSH "echo $(dec_to_hex $addr) > $DEBUGFS/hyp_free"
}

reclaim()
{
    $SSH "echo $(calc $ALLOCATOR_SIZE/4096) > $DEBUGFS/hyp_reclaim"
}

dump()
{
    $SSH "cat /sys//kernel/debug/dump_hyp_allocator"
}

log_and_die()
{
    echo "ERROR: $@"
    dump
    exit 1
}

test_end()
{
    DUMP=$(dump)

    [ -z $DUMP ] || log_and_die "Allocator not empty"
}

run()
{
    echo "Run $1...."
    eval $1
    test_end
    echo ".... Passed"
}

test_allocator_bounds()
{
    alloc $(calc $ALLOCATOR_SIZE-$CHUNK_HDR_SIZE)
    alloc 48 || true ## expected to fail
    free $CHUNK_HDR_SIZE
    reclaim
    alloc $ALLOCATOR_SIZE || true
}

test_discontiguous_mapped_regions()
{
    alloc 8192 # Also tests the min distance to the page start
    alloc 48
    free $CHUNK_HDR_SIZE
    reclaim
    free $(calc 8192+$CHUNK_HDR_SIZE+8+$CHUNK_HDR_SIZE)
    reclaim
}

test_no_reclaimable_pages()
{
    alloc 4096 # Also tests the min distance to the page start
    alloc 48
    free $CHUNK_HDR_SIZE
    reclaim # Should not reclaim anything
    free $(calc 4096+$CHUNK_HDR_SIZE+8+$CHUNK_HDR_SIZE)
    reclaim
}

test_recycle_split()
{
    alloc 4096
    alloc 48
    free $CHUNK_HDR_SIZE
    alloc 2048 # Split the first chunk
    alloc 2016 # no split due to the distance with the page start
    free $CHUNK_HDR_SIZE
    alloc 2040 # no split due to distance with the following chunk
    free $(calc 4096+$CHUNK_HDR_SIZE+8+$CHUNK_HDR_SIZE)
    free $(calc 2048+$CHUNK_HDR_SIZE+$CHUNK_HDR_SIZE)
    free $CHUNK_HDR_SIZE
    reclaim
}

test_merge_updown()
{
    alloc 48
    alloc 48
    alloc 48
    free $CHUNK_HDR_SIZE
    free $CHUNK_HDR_SIZE+48+$CHUNK_HDR_SIZE+48+$CHUNK_HDR_SIZE
    free $CHUNK_HDR_SIZE+48+$CHUNK_HDR_SIZE
    reclaim
}

test_aligned_chunks()
{
    alloc $(calc 4096-$CHUNK_HDR_SIZE)      # chunk1
    alloc $(calc "2*4096-$CHUNK_HDR_SIZE")  # chunk2
    alloc 64                                # chunk3
    free 4096+$CHUNK_HDR_SIZE               # free chunk2
    reclaim         # Should reclaim only one page from chunk2
    alloc 64        # Should be the new chunk2
    free 4096+$CHUNK_HDR_SIZE               # free chunk2
    free $CHUNK_HDR_SIZE
    free "3*4096+$CHUNK_HDR_SIZE"
    reclaim
}

run test_allocator_bounds
run test_discontiguous_mapped_regions
run test_no_reclaimable_pages
run test_recycle_split
run test_merge_updown
run test_aligned_chunks
