package org.scalacoin.script.interpreter

import org.scalacoin.protocol.script.{ScriptSignature, ScriptPubKey}
import org.scalacoin.script.arithmetic.{ArithmeticInterpreter, OP_ADD}
import org.scalacoin.script.bitwise.{OP_EQUAL, BitwiseInterpreter, OP_EQUALVERIFY}
import org.scalacoin.script.constant._
import org.scalacoin.script.control._
import org.scalacoin.script.crypto.{OP_SHA1, OP_CHECKSIG, OP_HASH160, CryptoInterpreter}
import org.scalacoin.script.reserved.NOP
import org.scalacoin.script.stack.{OP_DEPTH, StackInterpreter, OP_DUP}
import org.slf4j.LoggerFactory

import scala.annotation.tailrec

/**
 * Created by chris on 1/6/16.
 */
trait ScriptInterpreter extends CryptoInterpreter with StackInterpreter with ControlOperationsInterpreter
  with BitwiseInterpreter with ConstantInterpreter with ArithmeticInterpreter {

  private def logger = LoggerFactory.getLogger(this.getClass().toString)
  /**
   * Runs an entire script though our script programming language and
   * returns true or false depending on if the script was valid
   * @param stack
   * @param script
   * @return
   */
  def run(inputScript : List[ScriptToken], outputScript : List[ScriptToken]) : Boolean = {
    val fullInputScript = inputScript
    val fullOutputScript = outputScript
    val fullScript = inputScript ++ fullOutputScript

    @tailrec
    def loop(scripts : (List[ScriptToken], List[ScriptToken])) : Boolean = {
      val (stack,script) = (scripts._1, scripts._2)
      logger.debug("Stack: " + stack)
      logger.debug("Script: " + script)
      script match {
        //stack operations
        case OP_DUP :: t => loop(opDup(stack,script))
        case OP_DEPTH :: t => loop(opDepth(stack,script))

        //arithmetic operaetions
        case OP_ADD :: t => loop(opAdd(stack,script))

        //bitwise operations
        case OP_EQUAL :: t => {
          val (newStack,newScript) = equal(stack, script)
          if (newStack.head == ScriptTrue && newScript.size == 0) true
          else if (newStack.head == ScriptFalse && newScript.size == 0) false
          else loop(newStack,newScript)
        }
        case OP_EQUALVERIFY :: t => equalVerify(stack,script)._3
        //script constants
        //TODO: Implement these
        case ScriptConstantImpl(x) :: t if x == "1" => throw new RuntimeException("Not implemented yet")
        case ScriptConstantImpl(x) :: t if x == "0" => throw new RuntimeException("Not implemented yet")
        case (scriptNumberOp : ScriptNumberOperation) :: t => loop(scriptNumberOp.scriptNumber :: stack, t)
        case (scriptNumber : ScriptNumber) :: t => loop(pushScriptNumberBytesToStack(stack,script))
        case OP_PUSHDATA1 :: t => loop(opPushData1(stack,script))
        case OP_PUSHDATA2 :: t => loop(opPushData2(stack,script))
        case OP_PUSHDATA4 :: t => loop(opPushData4(stack,script))

        //TODO: is this right? I need to just push a constant on the input stack???
        case ScriptConstantImpl(x) :: t => loop((ScriptConstantImpl(x) :: stack, t))

        //control operations
        case OP_IF :: t => loop(opIf(stack,script))
        case OP_NOTIF :: t => loop(opNotIf(stack,script))
        case OP_ELSE :: t => loop(opElse(stack,script))
        case OP_ENDIF :: t => loop(opEndIf(stack,script))
        case OP_RETURN :: t => opReturn(stack,script)

        //crypto operations
        case OP_HASH160 :: t => loop(hash160(stack,script))
        case OP_CHECKSIG :: t => checkSig(stack,script,fullScript)
        case OP_SHA1 :: t => loop(opSha1(stack,script))

        //reserved operations
        case (nop : NOP) :: t => loop((stack,t))

        //no more script operations to run, True is represented by any representation of non-zero
        case Nil => stack.head != ScriptFalse
        case h :: t => throw new RuntimeException(h + " was unmatched")
      }
    }

    loop((List(),fullScript))
  }

  def run(inputScript : Seq[ScriptToken], outputScript : Seq[ScriptToken]) : Boolean = {
    run(inputScript.toList, outputScript.toList)
  }

  def run(scriptSignature : ScriptSignature, scriptPubKey : ScriptPubKey) : Boolean = {
    run(scriptSignature.asm, scriptPubKey.asm)
  }

}

object ScriptInterpreter extends ScriptInterpreter