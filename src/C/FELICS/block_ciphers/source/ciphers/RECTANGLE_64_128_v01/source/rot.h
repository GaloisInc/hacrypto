/*
 *
 * Kocaeli University Computer Engineering
 * TÜBİTAK BİLGEM, Turkey
 *
 * FELICS - Fair Evaluation of Lightweight Cryptographic Systems
 *
 * Copyright (C) 2016 Kocaeli University
 *
 * Written in 2016 by Adnan Baysal <adnan.baysal@tubitak.gov.tr>
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


#ifndef ROT_H
#define ROT_H

#define ROTL1(x)	(((x)<<1)^((x)>>15))
#define ROTL12(x)	(((x)<<12)^((x)>>4))
#define ROTL13(x)	(((x)<<13)^((x)>>3))
#define ROTR1(x)	(((x)<<15)^((x)>>1))
#define ROTR12(x)	(((x)<<4)^((x)>>12))
#define ROTR13(x)	(((x)<<3)^((x)>>13))

#endif /* ROT_H */

