# Bitcoin Core Block
#   Process a single Bitcoin block contained in a Bitcoin Core blk*.dat file.
#


# Return a BTC varint value. Presence of an argument causes the varint to be displayed as a Hex Fiend
# field with the argument as the label. The file pointer is left at the first byte past the varint field.
proc getVarint {args} {
  
    # Read the indicator byte
    set val [uint8]
    
    if {$val == 0xfd} {
      set val    [uint16]
      set type   "uint16"
      set moveit -2
    } elseif {$val == 0xfe} {
       set val    [uint32]
       set type   "uint32"
       set moveit -4
    } elseif {$val == 0xff} {
       set val    [uint64]
       set type   "uint64"
       set moveit -8
    } else {
       set moveit -1
       set type   "uint8"
    }
    
    if {[llength $args] == 1}  {
      move $moveit
      $type [lindex $args 0]
    }

    return $val
}

# Bitcoin Magic is 4 bytes (0xF9BEB4D9). Used as separator when storing Blocks and in the network messaging protocol 
set BTCMagic "F9 BE B4 D9"

requires 0 $BTCMagic

# Display the block metadata
bytes  4 "Magic"
uint32   "Block length"


# Display the block metadata
move  -4
bytes  4 "Magic"
uint32   "Block length"


# Process actual block data
section "Block header" {
  uint32 -hex "version"
  bytes 32    "prev blk hash"
  bytes 32    "Merkle root"
  unixtime32  "time"
  uint32      "bits"
  uint32      "nonce"
}

# get the number of transactions for the block
set blockTxnum [getVarint]

# There may be hundreds of transactions. Make a collapsed section to keep the overview initially brief.
section -collapsed "TX COUNT $blockTxnum"  {
  for {set tx 0} {$tx < $blockTxnum} {incr tx} {
    section -collapsed "Transaction $tx" {
      uint32 -hex "Tx version"
  
      # if next varint is 0 then we've read a (single byte) marker and it's a SegWit transaction.
      # if the varint is non-zero it's the actual number of inputs
      set nInputs [getVarint]
      if {$nInputs == 0} {
        # it's the marker and this is a SegWit transaction. read witness data later.
        set segwit 1
  
        # call out marker and flag byte
        move -1
        uint8 "marker"
        uint8 "flag"
        
        # now get the actual number of inputs
        set nInputs [getVarint]
      }  else {
        set segwit 0
      }
      
      # process the inputs
      section -collapsed "INPUT COUNT $nInputs"  {
        for {set k 0} {$k < $nInputs} {incr k} {
          section "Input $k" {
            bytes 32  "UTXO"
            uint32    "index"
  
            set nscriptbytes [getVarint "ScriptSig len"]
            if {$nscriptbytes > 0} {
              # if it's the Coinbase transaction and the first script byte is 0x3
              # then the next 3 bytes are the block height. must be 1st transaction
              # and 1st input
              set bheight [uint8]
              if {$tx == 0 && $k == 0 && $bheight == 3} {
                uint24 "height"
                move -3
              }
              # move back to beginning of script
              move -1
              bytes $nscriptbytes "ScriptSig"
            }

            uint32 -hex "nSequence"
          }
        }
      }
  
      # outputs
      set nOutputs [getVarint]
      
      # process the outputs
      section -collapsed "OUTPUT COUNT $nOutputs"  {
        for {set k 0} {$k < $nOutputs} {incr k} {
          section "Output $k" {
            uint64 "Satoshi"
            set nscriptbytes [getVarint "ScriptPubKey len"]
            bytes $nscriptbytes "ScriptPubKey"
          }
        }
      }
  
      #if it's a Segwit transaction process the witness data for each input
      if {$segwit} {
        section -collapsed "WITNESS DATA"  {
          # this is the witness data for each input
          for {set k 0} {$k < $nInputs} {incr k} {
            section "Witness Input $k" {
              set nwitstack [getVarint "STACK COUNT"]
              section -collapsed "Stack"  {
                for {set l 0} {$l < $nwitstack} {incr l} {
                  set nscriptbytes [getVarint]
                  if {$nscriptbytes > 0} {
                    bytes $nscriptbytes "item [expr $l + 1]: $nscriptbytes bytes"
                  } else {
                    move -1
                    bytes 1 "item [expr $l + 1]: 0 bytes"
                  }
                } ; # for each stack item
              }   ; # Section stack items
            }     ; # Section Witness input
          }       ; # for each input
        }         ; # Section Witness data
      }           ; # process Segwit data

      uint32 "nLockTime"

    } ; # Section single transaction
  } ; # for each transaction
} ; # Section all transactions
