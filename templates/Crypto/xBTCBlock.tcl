# Binary Template for Bitcoin Core Block content: expanded version
#   Process a single Bitcoin block contained in a Bitcoin Core blk*.dat file. 
#
#   Bitcoin Core blk*.dat files begin with 4 Magic bytes. These Magic bytes serve as a preamble to each block 
#   in the blk*.dat file. When invoked this template will align correctly on the initial block in the blk*.dat
#   file. Different blocks can be examined by using the Hex Fiend 'Anchor Template at Offset' feature and anchoring 
#   on any Magic bytes in the file.

#   By default ScriptSig, ScriptPubKey, and Witness data are simply labeled as Hex Fiend byte fields. Without using
#   the expansions cited below this Template simply displays the raw data for each Transaction in the block. Additional 
#   options for these data are avaialbale as follows. 
#
#     For each Transaction in the block this template will try and decode the contents of ScriptSig and ScriptPubKey 
#     accompanying inputs and outputs, respectively. After any non-null Hex Fiend byte field there will be a collapsed 
#     Hex Fiend Section called 'Decode'. Expanding this section will reveal a labeled version of the respective stack 
#     content.

#     For Witness data there may be multiple items for each input. Each stack item for each input is displayed as a 
#     Hex Fiend byte field. There is a separate 'Decode' Section for each item for each input.
#
#     The newest additions to Bitcoin Core (v 23.0.0) support Taproot. The decodings implemented here attempt to 
#     support P2TR 'key path' ScriptPubKey entries and Schnorr signatures in Witness data. P2TR 'script path' Witness 
#     data are not yet supported here.
#
# This Template is offered AS-IS. The 'Decode' sections are best effort. Additions and corrections welcomed.
#
# NOTE:  This Template will NOT run efficiently on machines earlier than M1 or M2 laptops.



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
# like a signature or public key. This proc is also used to process ScriptSig and ScriptPubKey trying to interpret data pushed 
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
      # Simple numeric value
      set type "stOP_81-96"
    } elseif {$len == 33 && ($op == 2  ||  $op == 3)} {
      # A compressed public key
      set type "stcPK"
    } elseif {$len == 65 && $op == 4} {
      # An uncompressed public key
      set type "stuPK"
    } elseif {$op == 0 && $op1 == 20} {
      set type "stOP0HASH20"
    } elseif {$op == 0 && $op1 == 32} {
      set type "stOP0HASH32"
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
  set auxval1 0   ; # Parameter of opcode
  set auxval2 0   ; # Location in string
  
  set opcode [string index $string $idx][string index $string [incr idx]]
  scan $opcode %x numericOC
 
  # First check for opcodes that do not have a singular representation
  if {$numericOC > 0  &&  $numericOC < 76} {
    set retval "OP_PUSH"
    set auxval1 $numericOC
    set auxval2 [expr $idx/2]
  } elseif {$numericOC > 80  &&  $numericOC < 97} {
    set retval "OP_1-16"
    set auxval1 [expr {$numericOC - 80}]
    set auxval2 [expr $idx/2]
  } else {
    # OK to now search the list
    set indx [lsearch $ncodes $opcode]
    if {$indx >= 0} {
      set retval [lindex $mcodes $indx]
    }
    set auxval2 [expr $idx/2]
  }
  
  # Post processing for special cases
  if {$retval == "OP_PUSHDATA1"} {
    incr idx 
    set opcode [string index $string $idx][string index $string [incr idx]]
    scan $opcode %x numericOC
    set auxval1 $numericOC
    set auxval2 [expr $idx/2]
  } elseif {$retval == "OP_PUSHDATA2" ||  $retval == "OP_PUSHDATA4"} {
    # These are not yet supported. Need to add processing of the multiple-byte length spec. Default to IDK
    set retval "OP_IDK"
  }
  
  if {$retval == "OP_IDK"} {
    set auxval1 $opcode
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

proc showSpecial {type len label flags} {
  if {[expr $flags & 2]} {
    section -collapsed "more" {
      uint8 $type
      uint8 "OP_PUSH"
      bytes $len $label
    }
  } else {
    uint8 $type
    uint8 "OP_PUSH"
    bytes $len $label
  }
}

# Display data previously interpreted from the stack. It is either Witness stack data or possibly data pushed in a ScriptSig or
# ScriptPubKey script.
#
# this procedure leaves the pointer at the end of the data
proc showStack {type len {flags 0}} { 
  set retval 1
                   
  switch $type {
    "stbadDER" {
      entry "short sig fails" $type
      set retval 0
    }
    "stDER" {
      # Might be a DER signature
      if {![decodeSig]} {
        set retval 0
      }
    }
    "stOP_81-96" {
      # Might be a multisig
      if {![decodeMultiSig]} {
        if {$len == 20} {
          bytes $len "<hash>"
        } else {
          bytes $len "nonMS bytes"
        }
      }
    }
    "stcPK" {
      # Might be a compressed public key
      if {![decodePubKey $len]} {
        set retval 0
      }
    }  
    "stuPK" {
      # Might be an uncompressed public key
      if {![decodePubKey $len]} {
        set retval 0
      }
    }
    "stOP1TRPUBK" {
      # Version 1 SegWit: Taproot
      showSpecial "OP_1" 32 "<P2TR PubKey>" $flags
#      uint8 "OP_1"
#      uint8 "OP_PUSH"
#      bytes 32 "<P2TR PubKey>"
    }
    "stOP0HASH20" {
      showSpecial "OP_0" 20 "<PubKey hash>" $flags
#      uint8 "OP_0"
#      uint8 "OP_PUSH"
#      bytes 20 "<PubKey hash>"
    }
    "stOP0HASH32" {
      showSpecial "OP_0" 32 "<Script hash>" $flags
#      uint8 "OP_0"
#      uint8 "OP_PUSH"
#      bytes 32 "<Script hash>"
    }
    "stOP_0" {
      move -1
      uint8 "OP_0" 
    }
    "stIDK" {
      # No specific clue to data on stack. There are a few cases we can guess.
      if {$len == 20 || $len == 32} {
        # Probably a key hash or a script hash
        bytes $len "<hash>"
      } elseif {[expr $flags & 1]} {
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
proc decodeParse {opcodes len {sats 0}} {

  move -$len
  set done 0
  set retval 1
  set flags 0
  set llen [llength $opcodes]
  
  section -collapsed "Decode" {
    for {set i 0} {$i < $llen  &&  $done == 0} {incr i} {
      set cur [lindex $opcodes $i]
      lassign $cur code a1 a2
      set ostr $code

      if {$code == "OP_1-16"} { 
        # See if this is the special case of SegWit Version 1 P2TR public key
        set type [decodeStack $a1]
        if {$type == "stOP1TRPUBK"} {
          set retval [showStack $type $a1 $flags]
          set done 1
        } else {
          set ostr [format "OP_%d" $a1]
          uint8 $ostr
        }
        set flags [expr $flags | 2]
      } elseif {$code == "OP_PUSHDATA1"} {
        set flags [expr $flags | 2]
        uint8 $ostr
        uint8 "push"
        set type [decodeStack $a1]
        set retval [showStack $type $a1 $flags]
        if {$retval == 0} {set done 1}
      } elseif {$code == "OP_PUSH"} {
        set flags [expr $flags | 2]
        uint8 $ostr
        set type [decodeStack $a1]
        set retval [showStack $type $a1 $flags]
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
          set flags [expr $flags | 1]
        }
      }
      set flags [expr $flags | 2]
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
set DEBUG 1
#end debug setup


set null ""
set exitMsg [format "Exit: normal"]
set ALLDONE 0

# BTC Magic is 4 bytes (0xF9BEB4D9) but it is more convenient to treat the 4 bytes as a little endian uint32.
set BTCMagic 0xD9B4BEF9

# Block Magic sanity check
if {[uint32] != $BTCMagic} {
  move -4
  set exitMsg [format "Exit: Bad Magic %4X" [hex 4] ]
  set ALLDONE 1
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

if {$ALLDONE == 0} {
  # There may be hundreds of transactions. Make a collapsed section to keep the overview initially brief.
  section -collapsed "TX COUNT $blockTxnum"  {
    for {set tx 0} {$tx < $blockTxnum && $ALLDONE == 0} {incr tx} {
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
          # flag must be non-zero (initally 1 -- see BIP 0141)
          uint8 "flag" 
        
          # now get the actual number of inputs
          set nInputs [getVarint]
        }  else {
          set segwit 0
        }
      
        # process the inputs.
        section -collapsed "INPUT COUNT $nInputs"  {
          for {set k 0} {$k < $nInputs && $ALLDONE == 0} {incr k} {  
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
                  set ALLDONE 1
                  continue
                }
                if {$tx != 0  ||  $k != 0} {
                  move -$nscriptbytes
                  set idSPK [hex $nscriptbytes]
                  set opcode [parseScript $nscriptbytes $idSPK]
  if {$DEBUG} {
                  # Look for target opcodes in list of those found.
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

                  if { ![decodeParse $opcode $nscriptbytes] } {
                    set exitMsg [format "Exit: ScriptSig decodeParse fail Tx: %d  input %d " $tx $k]
                    set ALLDONE 1
                    continue
                  } 
                }
              } else {
  if {$DEBUG} {
                for {set n 0} {$n < $nssTar} {incr n} {
                  set t [lindex $ssTarget $n] 
                  if {$t == ""} {
                    lappend op_ss [list $tx $k "<null>"]
                  }
                }
  }  
              } 

              uint32 -hex "nSequence"
            } 
          }
        }  
    
        # outputs
        set nOutputs [getVarint]
      
        # process the outputs
        section -collapsed "OUTPUT COUNT $nOutputs"  {
          for {set k 0} {$k < $nOutputs && $ALLDONE == 0} {incr k} {
            section "Output $k" {
              set sats [uint64]
              move -8
              uint64 "Satoshi"
              set nscriptbytes [getVarint "ScriptPubKey len"]
              if {$nscriptbytes <= 0} {
                set exitMsg [format "Exit: Output nscriptbytes (%d) is bogus Tx: %d output %d" $nscriptbytes $tx $k]
                set ALLDONE 1
                continue
              }
              bytes $nscriptbytes "ScriptPubKey"
              move -$nscriptbytes
              set idSPK [hex $nscriptbytes]
              set opcode [parseScript $nscriptbytes $idSPK]
  if {$DEBUG} {
              # Look for target opcodes in list of those found.
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
              if { ![decodeParse $opcode $nscriptbytes $sats] } {
                set exitMsg [format "Exit: ScriptPubKey decodeParse fail Tx: %d  output %d " $tx $k]
                set ALLDONE 1
                continue
              }         
            }
          }
        }

        #if it's a Segwit transaction process the witness data for each input
        if {$segwit} {
          section -collapsed "WITNESS DATA"  {
            # this is the witness data for each input
            for {set k 0} {$k < $nInputs && $ALLDONE == 0} {incr k} {
              section "Witness Input $k" {
                set nwitstack [getVarint "STACK COUNT"]
                section -collapsed "Stack"  {
                  for {set l 0} {$l < $nwitstack} {incr l} {  
                    set nscriptbytes [getVarint "item len"] 
                    if {$nscriptbytes > 0 } {
                      bytes $nscriptbytes "Stack item"    
                      move -$nscriptbytes
                      section -collapsed "Decode" {
                        set wType [decodeStack $nscriptbytes]
                        if {![showStack $wType $nscriptbytes]} { 
                          set exitMsg [format "Exit: Witness showSrack fail Tx: %d  input %d " $tx $k]
                          set ALLDONE 1
                          continue
                        }
                      }
                    } 
                  } ; # for each stack item
                }   ; # Section stack items   
              }     ; # Section Witness input   
            }       ; # for each input
          }         ; # Section Witness data
        }           ; # process Segwit data

        if {$ALLDONE == 0} {
          uint32 "nLockTime"
        } 
      } ; # Section single transaction
    } ; # for each transaction
  } ; # Section all transactions
} ; # ALLDONE == 0

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