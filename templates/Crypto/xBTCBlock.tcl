# Binary Temnplate for Bitcoin Core Block content
#   Process a single Bitcoin block contained in a Bitcoin Core blk*.dat file. 
#
#   Bitcoin Core blk*.dat files begin with 4 Magic bytes. These Magic bytes serve as a preamble to each block 
#   in the blk*.dat file. When invoked this template will align correctly on the inital block in the blk*.dat
#   file. Different blocks can be examined by using the Hex Fiend 'Anchor Template at Offset' feature and anchoring 
#   on any Magic bytes in the file.
#
#   For each Transaction in the block this version will try and decode the contents of any ScriptSig or ScriptPubKey 
#   accomapnying inputs and outputs, respectively. After each of these that has a non-zero entry there will be a 
#   collapsed Hex Fiend Section called 'Decode'. Expanding this section will reveal a labeled version of the 
#   respective stack content.

#   It will also try to interpret Witness data. Witness data are more general and are not structured except as 
#   determined by context. Witness items for each input are placed on the stack separately. Each stack item is 
#   labeled individually as it is encountered. There is no separate 'Decode' Section for the Witness stack items 
#   for each input.



# Return a BTC varint value. Presence of an argument causes the varint to be displayed as a Hex Fiend 
# field with the argument as the label. The file pointer is left at the first byte past the varint.
proc getVarint {{label ""}} {
  
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
    
    if {$label != ""}  {
      move $moveit
      $type $label
    }

    return $val
}

proc isPubKey {} {
  set klen [uint8]
  set op [uint8]
  move -2
  set retval 1
  
  if {$klen == 0x21} {
    # compressed key?
    if {$op != 2 && $op != 3} {
      set retval 0
    }
  } elseif {$klen == 0x41} {
    # uncompressed key?
    if {$op != 4} {
      set retval 0
    }
  } else {
    set retval 0
  }
  
  return $retval
}

proc decodePubKey {len} {
  set retval 1
  
  if {$len == 33} {
    bytes $len "Compressed PubKey"
  } elseif {$len == 65} {
    bytes $len "Uncompressed PubKey"
  } else {
    bytes $len "Unk Key"
    set retval 0
  }
  
  return $retval
}

proc decodeMultiSig {} {
  set OP_ [expr {[uint8] - 80} ]
  if {![isPubKey]} {
    move -1
    return 0
  }
  section -collapsed "m of n Multisig PubKeys" {
    move -1
    uint8 "m  (OP_$OP_)"
    set sigs 1
    while {$sigs} {
      set len [uint8]
      if {$len == 33 || $len == 65} {
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

proc isSignature {len}  {

  set curpos 0
  set DER [uint8]
  incr curpos
  if {$DER != 0x30} {
    move -$curpos
    return 0
  }
  
  set slen [uint8] 
  incr curpos
  if {[expr {$slen + 3}] != $len} {
    move -$curpos
    return 0
  }
  
  for {set i 0} {$i < 2} {incr i} {
    set intmrk [uint8]
    incr curpos
    if {$intmrk != 2} {
      move -$curpos
      return 0
    }
  
    set pslen [uint8]
    incr curpos
    if {[expr {$pslen + $curpos}] > $len} {
      move -$curpos
      return 0
    }
  
    move $pslen
    incr curpos $pslen
  }
  
  set sighash [uint8]
  incr curpos
  move -$curpos
  
  if {$curpos != $len} {
    return 0
  }
  
  return 1
}

# This proc tries to interpret contents of a Witness stack element. The witness stack elements each contain data whose length is
# specified by a preceeding byte count. Generally the data are not script though the data might represent an elemental structure
# like a signature or public key. This proc is also used when processing ScriptSig and ScriptPubKey to interpret data pushed 
# onto the stack. Typically in this case the data are elemental structures.
#
# this proc leaves the file pointer at the byte after the length spec.
proc decodeStack {len} {
  if {$len == 0} {
    set type "stOP_0"
  } else {
    set op  [uint8]
    set op1 [uint8]
    move -2
    
    if {$op == 0x30 && $len >= 67 &&  $len <= 73} {
      set type "stDER"
      set rv [isSignature $len]
      if {$rv == 0} {
        set type "stbadDER"
      }
    } elseif {$op == 81 && $op1 == 32} {
      # Version 1 SegWit: Taproot
      set type "stOP1TRPUBK"
    } elseif {$op >= 81 && $op <= 96} {
      set type "stOP_"
    } elseif {$len == 33 && ($op == 2  ||  $op == 3)} {
      set type "stcPK"
    } elseif {$len == 65 && $op == 4} {
      set type "stuPK"
    } elseif {$op == 0 && $op1 == 20} {
      set type "stOP0HASH"
    } else {
      set type "stIDK"
    }
  }
  return $type
}

proc getOP_CODE {string idx} {

  set ncodes { \
          "00" \
          "4C" \
          "4D" \
          "4E" \
          "6A" \
          "76" \
          "88" \
          "87" \
          "A9" \
          "AC" \ 
          "AE" \   
          "AF" \
       }
       
  set mcodes { \
          "OP_0" \
          "OP_PUSHDATA1" \
          "OP_PUSHDATA2" \
          "OP_PUSHDATA4" \
          "OP_RETURN" \
          "OP_DUP" \
          "OP_EQUALVERIFY" \
          "OP_EQUAL" \
          "OP_HASH160" \
          "OP_CHECKSIG" \    
          "OP_CHECKMULTISIG" \
          "OP_CHKMULTISIGVRFY" \
       }
       
  set retval  "OP_IDK"
  set auxval1 0
  set auxval2 0
  
  set opcode [string index $string $idx][string index $string [incr idx]]
  scan $opcode %x numericOC
 
  if {$numericOC > 0  &&  $numericOC < 76} {
    set retval "OP_PUSH"
    set auxval1 $numericOC
    set auxval2 [expr $idx/2]
  } elseif {$numericOC > 80  &&  $numericOC < 97} {
    set retval "OP_"
    set auxval1 [expr {$numericOC - 80}]
    set auxval2 [expr $idx/2]
  } else {
    set indx [lsearch $ncodes $opcode]
    if {$indx >= 0} {
      set retval [lindex $mcodes $indx]
    }
    set auxval2 [expr $idx/2]
  }
  
  if {$retval == "OP_PUSHDATA1"} {
    incr idx 
    set opcode [string index $string $idx][string index $string [incr idx]]
    scan $opcode %x numericOC
    set auxval1 $numericOC
    set auxval2 [expr $idx/2]
  }
  
  if {$retval == "OP_IDK"} {
    set auxval1 $opcode
    set auxval2 [expr ($idx - 1)/2]
    set auxval2 [expr $idx/2]
  }
  
  return [list $retval $auxval1 $auxval2]
}

proc parseScript {len script}  {

  set pos [expr $len * 2 + 2]
  set opcode {}
  set tmplist {}
  
    for {set i 2} {$i < $pos} {incr i 2} {
      set opcode [getOP_CODE $script $i]

      lassign $opcode cmd auxval1 auxval2
      lappend tmplist $opcode
    
      if {$cmd == "OP_IDK"} {return $tmplist}
      if {$cmd == "OP_PUSH"} {
        # skip over the bytes pushed
        incr i [expr $auxval1*2]
      }
      if {$cmd == "OP_PUSHDATA1"} {
        # skip over the byte count and the bytes pushed
        incr i [expr $auxval1*2 + 2]
      }
    }

    return $tmplist
}

# Display data previously interpreted from the stack. It is either Witness stack data or possibly data pushed in a ScriptSig or
# ScriptPubKey script.
#
# this procedure leaves the pointer at the end of the data
proc showStack {type len {opret 0}} { 
  set retval 1
                   
  switch $type {
    "stOP1TRPUBK" {
      # Version 1 SegWit: Taproot
      uint8 "OP_1"
      uint8 "OP_PUSH"
      bytes 32 "<TR PubKey>"
    }
    "stbadDER" {
      entry "short sig fails" $type
      set retval 0
    }
    "stDER" {
      if {![decodeSig]} {
        set retval 0
      }
    }
    "stOP_" {
      if {![decodeMultiSig]} {
        if {$len == 20} {
          bytes $len "<hash>"
        } else {
          bytes $len "nonMS bytes"
        }
      }
    }
    "stcPK" {
      if {![decodePubKey $len]} {
        set retval 0
      }
    }  
    "stuPK" {
      if {![decodePubKey $len]} {
        set retval 0
      }
    }
    "stOP0HASH" {
      section -collapsed "more" {
        uint8 "OP_0"
        uint8 "OP_PUSH"
        bytes 20 "<hash>"
      }
    }
    "stOP_0" {
      move -1
      uint8 "OP_0" 
    }
    "stIDK" {
      # No specific clue to data on stack. There are a few cases we can guess.
      if {$len == 20} {
        # Probably a key or script hash
        bytes $len "<hash>"
      } elseif {$opret != 0} {
        # Arbitrary data (sometimes printable characters) after an OP_RETURN (which guarantees script result is not TRUE)
        bytes $len "<data>"
      } else {
        # I Don't Know
        bytes $len "IDK bytes"
      }
    }
    default {
      entry "unknown stack data type" $type
      set retval 0
    }
  }
  return $retval
}

# Display script detail for each opcode discovered in ScriptSig or ScriptPubKey item.
proc decodeParse {opcodes len whoami {sats 0}} {

  move -$len
  set done 0
  set retval 1
  set opret 0
  set llen [llength $opcodes]
  
  section -collapsed "Decode" {
    for {set i 0} {$i < $llen  &&  $done == 0} {incr i} {
      set cur [lindex $opcodes $i]
      lassign $cur code a1 a2
      set ostr $code
      
      if {$code == "OP_"} {
        if {$llen == 2  &&  $whoami == "ScriptPubKey"} {
          # See if this is the special case of SegWit Version 1 P2TR public key
          set type [decodeStack $a1]
          if {$type == "stOP1TRPUBK"} {
            set retval [showStack $type $a1]
            set done 1
          }
        } else {
          set ostr $code$a1
          uint8 $ostr
        }
      } elseif {$code == "OP_PUSHDATA1"} {
        uint8 $ostr
        uint8 "push"
        set type [decodeStack $a1]
        set retval [showStack $type $a1 $opret]
        if {$retval == 0} {set done 1}
      } elseif {$code == "OP_PUSH"} {
        uint8 $ostr
        set type [decodeStack $a1]
        set retval [showStack $type $a1 $opret]
        if {$retval == 0} {set done 1}
      } elseif {$code == "OP_IDK"} {
        entry "Decode Opcode" $cur
        set retval 0
        set done 1
      } else {
        uint8 $ostr
        if {$code == "OP_RETURN"} {
          if {$sats != 0} {
            entry "(Sats unspendable)" ""
          }
          # provide context to subsequent procs that because of OP_RETURN the script will fail 
          set opret 1
        }
      }
    }
  }
  
  return $retval
}

# ***********************************************************************************************************************

#debug setup
set op_ss  {}
set ssTarget {}
set nssTar [llength $ssTarget]

set op_spk {}
set spkTarget {}
set nspkTar [llength $spkTarget]

set debugMsgs {}
#end debug setup



set null ""
set exitMsg [format "Exit: normal"]
set done 0

# BTC Magic is 4 bytes (0xF9BEB4D9) but it is more convenient to treat the 4 bytes as a little endian uint32.
set BTCMagic 0xD9B4BEF9

# Block Magic sanity check
if {[uint32] != $BTCMagic} {
  move -4
  set exitMsg [format "Exit: Bad Magic %4X" [hex 4] ]
  set done 1
} else {

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
}

if {$done == 0} {
# There may be hundreds of transactions. Make a collapsed section to keep the overview initially brief.
section -collapsed "TX COUNT $blockTxnum"  {
  for {set tx 0} {$tx < $blockTxnum && $done == 0} {incr tx} {
    section -collapsed "Transaction $tx" {     
#      set ScriptSigOpcodes {}
#      set ScriptPubKeyOpcodes {}
#      set WitnessOpcodes {}
#      set ScriptSigOpcodesArray {}
#      set ScriptPubKeyOpcodesArray {}
#      set WitnessOpcodesArray {}

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
        # flag must be non-zero (initally 1 -- see BIP 0141)
        uint8 "flag" 
        
        # now get the actual number of inputs
        set nInputs [getVarint]
      }  else {
        set segwit 0
      }
      
      # process the inputs.
      section -collapsed "INPUT COUNT $nInputs"  {
        for {set k 0} {$k < $nInputs && $done == 0} {incr k} {  
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
              if {$nscriptbytes < 0} {
                set exitMsg [format "Exit: OInput nscriptbytes (%d) is bogus Tx: %d input %d" $nscriptbytes $tx $k]
                set done 1
                continue
              }
              if {$tx != 0  ||  $k != 0} {
                move -$nscriptbytes
                set idSPK [hex $nscriptbytes]
                set opcode [parseScript $nscriptbytes $idSPK]
if {1} {
  for {set n 0} {$n < $nssTar} {incr n} {
    set t [lindex $ssTarget $n]
    for {set m 0} {$m < [llength $opcode]} {incr m} {
      set oc [lindex [lindex $opcode $m] 0]
      if {$oc ==  $t} {
        lappend op_ss [list $tx $k $t]
      }
    }
  }
}

                if { ![decodeParse $opcode $nscriptbytes "ScriptSig"] } {
                  set exitMsg [format "Exit: ScriptSig decodeParse fail Tx: %d  input %d " $tx $k]
                  set done 1
                  continue
                } 
#                lappend ScriptSigOpcodes $opcode
              }
          } else {
#                lappend ScriptSigOpcodes "<null>"
          } 

            uint32 -hex "nSequence"
          }
        }
#        lappend ScriptSigOpcodesArray $ScriptSigOpcodes
      }  
    
      # outputs
      set nOutputs [getVarint]
      
      # process the outputs
      section -collapsed "OUTPUT COUNT $nOutputs"  {
        for {set k 0} {$k < $nOutputs && $done == 0} {incr k} {
          section "Output $k" {
            set sats [uint64]
            move -8
            uint64 "Satoshi"
            set nscriptbytes [getVarint "ScriptPubKey len"]
            if {$nscriptbytes <= 0} {
              set exitMsg [format "Exit: Output nscriptbytes (%d) is bogus Tx: %d output %d" $nscriptbytes $tx $k]
              set done 1
              continue
            }
            bytes $nscriptbytes "ScriptPubKey"
            move -$nscriptbytes
            set idSPK [hex $nscriptbytes]
            set opcode [parseScript $nscriptbytes $idSPK]
if {1} {
  for {set n 0} {$n < $nspkTar} {incr n} {
    set t [lindex $spkTarget $n]
    for {set m 0} {$m < [llength $opcode]} {incr m} {
      set oc [lindex [lindex $opcode $m] 0]
      if {$oc ==  $t} {
        lappend op_spk [list $tx $k $t]
      }
    }
  }
}
            if { ![decodeParse $opcode $nscriptbytes "ScriptPubKey" $sats] } {
              set exitMsg [format "Exit: ScriptPubKey decodeParse fail Tx: %d  output %d " $tx $k]
              set done 1
              continue
            }         
#            lappend ScriptPubKeyOpcodes $opcode
          }
        }
#        lappend ScriptPubKeyOpcodesArray $ScriptPubKeyOpcodes
      }

      #if it's a Segwit transaction process the witness data for each input
      if {$segwit} {
        section -collapsed "WITNESS DATA"  {
          # this is the witness data for each input
          for {set k 0} {$k < $nInputs && $done == 0} {incr k} {
            section "Witness Input $k" {
              set nwitstack [getVarint "STACK COUNT"]
              section -collapsed "Stack"  {
                for {set l 0} {$l < $nwitstack} {incr l} {  
                  set nscriptbytes [getVarint "item len"]     
                  set wType [decodeStack $nscriptbytes]
                  if {![showStack $wType $nscriptbytes]} {
                    set exitMsg [format "Exit: Witness showSrack fail Tx: %d  input %d " $tx $k]
                    set done 1
                    continue
                  }
                } ; # for each stack item
              }   ; # Section stack items   
            }     ; # Section Witness input   
          }       ; # for each input
#          lappend WitnessOpcodesArray $WitnessOpcodes
        }         ; # Section Witness data
      }           ; # process Segwit data

      if {$done == 0} {uint32 "nLockTime"} 

    } ; # Section single transaction
  } ; # for each transaction
} ; # Section all transactions
} ; # done == 0

entry " " $null
entry $exitMsg $null
entry " " $null



# debug/instrumentation

for {set i 0} {$i < [llength $debugMsgs]} {incr i} {
  entry [lindex $debugMsgs $i] $null
}

if {[llength $op_ss] > 0} {
  entry "SS Target opcodes" $ssTarget
  entry "op_ss len" [llength $op_ss]
  section -collapsed "op_ss" {
    for {set i 0} {$i < [llength $op_ss]}  {incr i} {
     entry [format "op_ss %d" $i] [lindex $op_ss $i]
    }
  }
}

if {[llength $op_spk] > 0} {
  entry "SPK Target opcodes" $spkTarget
  entry "op_spk len" [llength $op_spk]
  section -collapsed "op_spk" {
    for {set i 0} {$i < [llength $op_spk]}  {incr i} {
      entry [format "op_spk %d" $i] [lindex $op_spk $i]
    }
  }
}

# end debug/instrumentation