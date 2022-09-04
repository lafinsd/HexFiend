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
proc decodePubKey {len} {
  bytes $len "PubKey"
  return 1
}

proc decodeMultiSig {} {
  set OP_ [expr {[uint8] - 80} ]
  section -collapsed "Multisig" {
    move -1
    uint8 "m  (OP_$OP_)"
    set sigs 1
    while {$sigs} {
      set len [uint8]
      if {$len == 33} {
        decodePubKey $len
      } else {
        move -1
        set sigs 0
      }
    }
    
    set OP_ [expr {[uint8] - 80} ]
    move -1
    uint8 "n  (OP_$OP_)"
    
    set op [uint8]
    if {$op == 0xae} {
      set type "OP_CHECKMULTISIG"
    } elseif {$op == 0xaf} {
      set type "OP_CHECKMULTISIGVERIFY"
    } else {
      set type "OP_IDK"
    }
    move -1
    uint8 "$type" 
  }
  return 1
}

proc decodeSig {} {
  section -collapsed "Signature" {
    uint8 -hex "DER"
    uint8 "struct length"
    uint8 "integer marker"
    set r [uint8]
    move -1
    uint8 "r length"
    bytes $r "r"
    uint8 "integer marker"
    set s [uint8]
    move -1
    uint8 "s length"
    bytes $s "s"
    uint8 "SIGHASH flag"
  }
  return 1
}

proc witnessType {len} {
  if {$len == 0} {
    set type "<null>"
  } else {
    set op [uint8]
    move -1

    if {$op == 0x30 && $len >= 67 &&  $len <= 73} {
      set type "wtDER"
    } elseif {$op >= 0x51 && $op <= 0x60 && $len != 32} {
      set type "wtOP_"
    } elseif {$len == 33 && ($op == 2  ||  $op == 3)} {
      set type "wtPK"
    } else {
      set type "wtIDK"
    }
  }
  return $type
}

# BTC Magic is 4 bytes (0xF9BEB4D9) but it is more convenient to treat the 4 bytes as a little endian uint32.
set BTCMagic 0xD9B4BEF9


# Block Magic sanity check
if {[uint32] != $BTCMagic} {
  move -4
  set cur [pos]
  error "[format "Bad Magic %4X at %d (0x%X)" [hex 4] $cur $cur ]"
}

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

list scriptsiglens
list versionbyte
list lengthbyte
list scriptsigpos

# get the number of transactions for the block
set blockTxnum [getVarint]

# There may be hundreds of transactions. Make a collapsed section to keep the overview initially brief.
section -collapsed "TX COUNT $blockTxnum"  {
  for {set tx 0} {$tx < $blockTxnum} {incr tx} {
    section -collapsed "Transaction $tx at [pos]" {
#if {$tx == 1490} {return}      
      set aScriptSigNotZero 0
      uint32 -hex "Tx version"
  
      # if next varint is 0 then we've read a (single byte) marker and it's a SegWit transaction. 
      # if the varint is non-zero it's the actual number of inputs
      set nInputs [getVarint]
      if {$nInputs == 0} {
        # it's the marker and this is a SegWit transaction. read witness data later.
        set segwit 1
        # reset lists used for SegWit
        set scriptsiglens {}
        set versionbyte {}
        set lengthbyte {}
  
        # call out marker and flag byte
        move -1
        uint8 "marker"
        # flag must be non-zero (initally 1 -- see BIP 0141)
        uint8 "flag" 
        
        # now get the actual number of inputs
        set nInputs [getVarint]
      }  else {
        set segwit 0
      }
      
      set aScriptSigNotZero 0
      # process the inputs.
      section -collapsed "INPUT COUNT $nInputs"  {
        for {set k 0} {$k < $nInputs} {incr k} {  
          section "Input $k" {
            bytes 32  "UTXO"
            uint32    "index"
            set nscriptbytes [getVarint "ScriptSig len"]
            
            if {$segwit} {
              lappend scriptsiglens $nscriptbytes
              lappend scriptsigpos [pos]
            }
            
            if {$nscriptbytes > 0} {
              incr aScriptSigNotZero
              # if it's the Coinbase transaction and the first script byte is 0x3
              # then the next 3 bytes are the block height. must be 1st transaction
              # and 1st input
              set bheight [uint8]
              if {$tx == 0 && $k == 0 && $bheight == 3} { 
                uint24 "height"
                move -3 
              } else {
                # if this is SegWit this could be a version byte with a length byte to follow
                if {$segwit} {
                  lappend versionbyte [uint8]
                  lappend lengthbyte [uint8]
                  move -2              
                }
              }
              # move back to beginning of script 
              move -1
              bytes $nscriptbytes "ScriptSig"
            } else {
              if {$segwit} {
                lappend versionbyte ""
                lappend lengthbyte ""
              }
            }

            uint32 -hex "nSequence"
          }
        }
      }  
      
if {0 && $segwit} {
entry "list len" [llength $scriptsiglens]      
for {set k 0} {$k < $nInputs} {incr k} {
  entry "ScriptSig length" [lindex $scriptsiglens $k]
  entry "Version " [lindex $versionbyte $k]
  entry "script length" [lindex $lengthbyte $k]
  entry "scriptsig pos" [lindex $scripsigpos $k]
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
if {$nscriptbytes == 0} {return}
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
                  set wType [witnessType $nscriptbytes]
if {$tx == 1505 && $l == 0 && $k == 2} {
                    entry "entry nsb" $nscriptbytes
                    entry "entry wType" $wType
                    return
}
set parse 1
if {($tx != 0) && $parse} {                  
                  switch $wType {
                    "wtDER" {
                      if {![decodeSig]} {
                        return
                      }
                    }
                    "wtOP_" {
                      if {![decodeMultiSig]} {
                        return
                      }
                    }
                    "wtPK" {
                      if {![decodePubKey $nscriptbytes]} {
                        return
                      }
                    }
                    "<null>" {
                      move -1
                      uint8 "<null>" 
                    }
                    "wtIDK" {
                      if {$nscriptbytes > 400} {
                        entry "nsb too big" $nscriptbytes
                        return
                      }
                      bytes $nscriptbytes "item [expr $l + 1]"
                      #return
                    }
                    default {
                      entry "unknown witness data type" $wType
                      return
                    }
                  }
} else {                    
                  if {$nscriptbytes > 0} {
                      bytes $nscriptbytes "item [expr $l + 1]"
                  } 
}
                } ; # for each stack item
              }   ; # Section stack items   
            }     ; # Section Witness input   
          }       ; # for each input
        }         ; # Section Witness data
      }           ; # process Segwit data

      uint32 "nLockTimee"

    } ; # Section single transaction
  } ; # for each transaction
} ; # Section all transactions
