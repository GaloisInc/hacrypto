/*
 *
 * National Security Research Institute
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2015 National Security Research Institute
 *
 * Written in 2015 by Youngjoo Shin <yjshin@nsr.re.kr>
 *
 * This file is part of FELICS.
 *
 * FELICS is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * FELICS is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 */

.macro ROR1 Dh,Dl,T   
  CLR \T            
  RRA \Dh           
  RRC \Dl           
  RRC \T            
  AND #0x7FFF, \Dh  
  ADD \T, \Dh     
.endm

.macro ROR3 Dh,Dl,T   
  CLR \T            
  RRA \Dh           
  RRC \Dl           
  RRC \T            
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  AND #0x1FFF, \Dh  
  ADD \T, \Dh     
.endm                 

.macro  ROR5 Dh,Dl,T  
  CLR \T          
  RRA \Dh         
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  AND #0x7FF, \Dh 
  ADD \T, \Dh     
.endm                 

.macro ROR7 Dh,Dl,T   
  CLR \T            
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  AND #0x1FF, \Dh 
  ADD \T, \Dh     
.endm                 

.macro ROR8 Dh,Dl,T0,T1
  mov.b \Dl,\T0
  mov.b \Dh,\T1
  and   #0xff00, \Dh
  and   #0xff00, \Dl
  add   \T1, \Dl
  add   \T0, \Dh
  swpb  \Dh
  swpb  \Dl
.endm

.macro ROR9a Dh,Dl,T0,T1
  ROR8  \Dh,\Dl,\T0,\T1
  ROR1  \Dh,\Dl,\T0
.endm

.macro ROR9 Dh,Dl,T   
  CLR \T            
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T           
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  RRA \Dh           
  RRC \Dl           
  RRC \T          
  AND #0x7F, \Dh  
  ADD \T, \Dh     
.endm                 

.macro ROL8 Dh,Dl,T0,T1
  swpb  \Dl
  swpb  \Dh
  mov.b \Dl, \T0
  mov.b \Dh, \T1
  and   #0xff00, \Dl
  and   #0xff00, \Dh
  add   \T1, \Dl
  add   \T0, \Dh
.endm

.macro ROL1 Dh,Dl 
  rla \Dh         
  rlc \Dl         
  adc \Dh         
.endm             

.macro ROL3 Dh,Dl 
  ROL1 \Dh,\Dl    
  ROL1 \Dh,\Dl    
  ROL1 \Dh,\Dl    
.endm             

.macro ROL5 Dh,Dl 
  ROL1 \Dh,\Dl    
  ROL1 \Dh,\Dl    
  ROL1 \Dh,\Dl    
  ROL1 \Dh,\Dl    
  ROL1 \Dh,\Dl    
.endm             

.macro ROL6 Dh,Dl 
  ROL3  \Dh,\Dl   
  ROL3  \Dh,\Dl   
.endm             

.macro ROL9 Dh,Dl,T0,T1
  ROL8 \Dh,\Dl,\T0,\T1
  ROL1 \Dh,\Dl
.endm

.macro ROL11 Dh,Dl
  ROL6  \Dh,\Dl   
  ROL3  \Dh,\Dl   
  ROL1  \Dh,\Dl   
  ROL1  \Dh,\Dl   
.endm             

.macro ROL11a Dh,Dl,T0,T1
  ROL8  \Dh,\Dl,\T0,\T1   
  ROL3  \Dh,\Dl   
.endm             
