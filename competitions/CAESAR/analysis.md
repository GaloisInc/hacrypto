Cryptographic competitions

-------------------------------------------------------------------------------

CAESAR submissions
Second-round candidates (alphabetical order):

+--------------------------------------------------------------+
|    candidate    |                 designers                  |
|-----------------+--------------------------------------------|
|ACORN: v1 v2     |Hongjun Wu                                  |
|-----------------+--------------------------------------------|
side conditions on algorithm parameters and return values (e.g., keys
are generated in secure and random way, typical side conditions on IV,
key x IV pair should not be used to protect more than one message, key
x IV pair should not be used with two different tag sizes,
verification failure => the decrypted paintext and incorrect
authentication tag remain secret).  success rate of a single forgery
attack is F(); multiple forgery attacks is G().  state and key cannot
be recovered faster than exhaustive key search.  if IV is reused 7
times then security is lost.  nonce reuse, linear, differential, cube,
correlation attacks all mentioned.  claim of a nonlinear state update
function (statistical correlation between any two states vanishes
quickly as the distance bewteen them increases
[what is a state and what is distance?].  input difference analysis of
LFSRs via linear recurrence analysis.  differential analysis of
nonlinear subfunctions.  relationship between the probability of
eliminating the difference in state => a specific strength MAC
security.  claim of # of steps that can be executed in parallel =>
software speed.  claims about hardware size and energy efficiency as
well as size of software implementation.  claims about size and values
of padding bits.  claim that tap distances that are prime or
contain a large prime factor.
|-----------------+--------------------------------------------|
|AEGIS: v1        |Hongjun Wu, Bart Preneel                    |
|-----------------+--------------------------------------------|


|-----------------+--------------------------------------------|
|AES-COPA: v1 v2  |Elena Andreeva, Andrey Bogdanov, Atul Luykx,|
|                 |Bart Mennink, Elmar Tischhauser, Kan Yasuda |
|-----------------+--------------------------------------------|
security levels in log_2 of number of calls to known primitive (e.g.,
AES) for several security claims (e.g., confidentiality or integrity
of a specific piece of state).  claims about invariants of nonces
(e.g., unique, reused, common prefix, random, etc.).  claim of SPRP.
claim that a cipher is online vs. offline, streaming vs. (potentially
large) block.  claims of computational cost under various scenarios
(e.g., key agility, nonce agility where agility means what is the cost
when a new parameter value is used?).  claims of preprocessing of
certain data (e.g., AD and plaintext) akin to partial evaluation.
claim that a design style has been used, e.g., PMAC or OMAC.  claim
that any implementation does not need certain operations (e.g.,
GF(2^128) multiplications).  claim that there are no weak keys.

|-----------------+--------------------------------------------|
|AES-JAMBU: v1 v2 |Hongjun Wu, Tao Huang                       |
|-----------------+--------------------------------------------|

Claims about maximal memory use in operation.

|-----------------+--------------------------------------------|
|AES-OTR: v1 v2   |Kazuhiko Minematsu                          |
|-----------------+--------------------------------------------|
Claim that a construct is a PRF or a PMAC.  Claim that length of data
(e.g., a nonce) can be changed without changing another piece of data
(e.g., key) with no implications on security.  Claims of security
goals in terms of both data and time (log_2).  Claim of
inverse-freeness [4: 18].  Claim of smaller ROM and RAM consumption.
Claim that an algorithm is pipelinable.  Claim that a function is an
involution.

|-----------------+--------------------------------------------|
|AEZ: home v1     |Viet Tung Hoang, Ted Krovetz, Phillip       |
|security v3 v4   |Rogaway                                     |
|-----------------+--------------------------------------------|
Efficiency claimed as a ratio of an existing primitive (i.e.,
AES-equivalents).

|-----------------+--------------------------------------------|
|Ascon: home v1   |Christoph Dobraunig, Maria Eichlseder,      |
|v1.1             |Florian Mendel, Martin Schl?ffer            |
|-----------------+--------------------------------------------|
Claim of maximum differential probability and differential branch
number of an S-box, and maximal linear probability and linear branch
number of an S-box.  Analysis of, and claims about, algebraic degree
of a polynomial representation of a construct.  Claims about
implication of reducing number of rounds within an algorithm.  Use of
a heuristic search tool to find good differential and linear trails
for more rounds to approach a bound.  Also for collision-producing
differentials and impossible differentials.  Claim of efficient
implementation of side-channel resistence features.  Claim of
symmetric performance for encyption and decryption.  Claim about the
entropy of a constant (e.g,. number of rounds) as counter-evidence for
the existence of a backdoor.  Claim that an S-box is invertible, has
no fix-points, pipelinable, amenable to bit-slicing, relationship
between each output bit and a # of input bits, low algebraic degree to
facilitate masking and threshold implementations, maximum differential
and linear probability of P, differential and linear branch number is
B, and avoid trivially iterable differential properties in the message
injection positions.  Claim of compactness and use of relatively few
instructions (?).

|-----------------+--------------------------------------------|
|CLOC and SILC:   |Tetsu Iwata, Kazuhiko Minematsu, Jian Guo,  |
|clocv1 silcv1    |Sumio Morioka, Eita Kobayashi               |
|clocv2 silcv2    |                                            |
|-----------------+--------------------------------------------|

Nothing new.

|-----------------+--------------------------------------------|
|Deoxys: home v1  |                                            |
|ordering addendum|J?r?my Jean, Ivica Nikoli?, Thomas Peyrin   |
|v1.3             |                                            |
|-----------------+--------------------------------------------|

Claims about performance for small messages vs. large messages.  Claim
about smooth parameters handling---client can pick its own variant of
the inner tweakable block cipher by adapting key and tweak sizes at
their convenience.

|-----------------+--------------------------------------------|
|ELmD: v1         |                                            |
|clarification    |Nilanjan Datta, Mridul Nandi                |
|v2.0             |                                            |
|-----------------+--------------------------------------------|

No new information.

|-----------------+--------------------------------------------|
|HS1-SIV: v1 nh v2|Ted Krovetz                                 |
|-----------------+--------------------------------------------|

No new information.

|-----------------+--------------------------------------------|
|                 |Pawe? Morawiecki, Kris Gaj, Ekawat          |
|ICEPOLE: v1      |Homsirikamol, Krystian Matusiewicz, Josef   |
|addendum v2      |Pieprzyk, Marcin Rogawski, Marian Srebrny,  |
|                 |Marcin W?jcik                               |
|-----------------+--------------------------------------------|
|Joltik: home v1  |                                            |
|ordering addendum|J?r?my Jean, Ivica Nikoli?, Thomas Peyrin   |
|v1.3             |                                            |
|-----------------+--------------------------------------------|
|Ketje: home v1   |Guido Bertoni, Joan Daemen, Micha?l Peeters,|
|extendeddoc      |Gilles Van Assche, Ronny Van Keer           |
|-----------------+--------------------------------------------|
|Keyak: home v1   |Guido Bertoni, Joan Daemen, Micha?l Peeters,|
|addendum v2      |Gilles Van Assche, Ronny Van Keer           |
|-----------------+--------------------------------------------|
|Minalpher: v1    |Yu Sasaki, Yosuke Todo, Kazumaro Aoki,      |
|v1.1             |Yusuke Naito, Takeshi Sugawara, Yumiko      |
|                 |Murakami, Mitsuru Matsui, Shoichi Hirose    |
|-----------------+--------------------------------------------|
|MORUS: v1        |                                            |
|figure1-corrected|Hongjun Wu, Tao Huang                       |
|v1.1             |                                            |
|-----------------+--------------------------------------------|
|NORX: home v1    |Jean-Philippe Aumasson, Philipp Jovanovic,  |
|v2.0             |Samuel Neves                                |
|-----------------+--------------------------------------------|
|OCB: v1          |Ted Krovetz, Phillip Rogaway                |
|-----------------+--------------------------------------------|
|                 |Simon Cogliani, Diana-?tefania Maimu?, David|
|OMD: v1.0 v2.0   |Naccache, Rodrigo Portella do Canto, Reza   |
|                 |Reyhanitabar, Serge Vaudenay, Damian Viz?r  |
|-----------------+--------------------------------------------|
|PAEQ: home v1    |Alex Biryukov, Dmitry Khovratovich          |
|ordering         |                                            |
|-----------------+--------------------------------------------|
|?-Cipher: v1     |Danilo Gligoroski, Hristina Mihajloska,     |
|newpad v2 v2.0   |Simona Samardjiska, H?kon Jacobsen, Mohamed |
|                 |El-Hadedy, Rune Erlend Jensen, Daniel Otte  |
|-----------------+--------------------------------------------|
|POET: home v1    |Farzaneh Abed, Scott Fluhrer, John Foley,   |
|ordering nomult  |Christian Forler, Eik List, Stefan Lucks,   |
|v2.0             |David McGrew, Jakob Wenzel                  |
|-----------------+--------------------------------------------|
|                 |Elena Andreeva, Beg?l Bilgin, Andrey        |
|PRIMATEs: home v1|Bogdanov, Atul Luykx, Florian Mendel, Bart  |
|ordering v1.02   |Mennink, Nicky Mouha, Qingju Wang, Kan      |
|                 |Yasuda                                      |
|-----------------+--------------------------------------------|
|SCREAM (without  |Vincent Grosso, Ga?tan Leurent,             |
|iSCREAM): v1     |Fran?ois-Xavier Standaert, Kerem Varici,    |
|ordering v3      |Anthony Journault, Fran?ois Durvaux, Lubos  |
|                 |Gaspar, St?phanie Kerckhof                  |
|-----------------+--------------------------------------------|
|SHELL: v1        |Lei Wang                                    |
|corrections v2.0 |                                            |
|-----------------+--------------------------------------------|
|STRIBOB: home v1 |Markku-Juhani O. Saarinen, Billy B. Brumley |
|v2               |                                            |
|-----------------+--------------------------------------------|
|Tiaoxin: v1.0    |Ivica Nikoli?                               |
|v2.0             |                                            |
|-----------------+--------------------------------------------|
|TriviA-ck: v1 v2 |Avik Chakraborti, Mridul Nandi              |
+--------------------------------------------------------------+
 Additional first-round candidates (alphabetical order):
 +--------------------------------------------------------------+
|    candidate    |                 designers                  |
|-----------------+--------------------------------------------|
|++AE: v1.0       |                                            |
|analysis         |Francisco Recacha                           |
|parameters       |                                            |
|nopatent         |                                            |
|-----------------+--------------------------------------------|
|AES-CMCC: v1 v1.1|Jonathan Trostle                            |
|-----------------+--------------------------------------------|
|[S:AES-COBRA:S]: |Elena Andreeva, Andrey Bogdanov, Martin M.  |
|v1 withdrawn     |Lauridsen, Atul Luykx, Bart Mennink, Elmar  |
|                 |Tischhauser, Kan Yasuda                     |
|-----------------+--------------------------------------------|
|AES-CPFB: v1     |Miguel Montes, Daniel Penazzi               |
|-----------------+--------------------------------------------|
|Artemia: v1 proof|Javad Alizadeh, Mohammad Reza Aref, Nasour  |
|addendum v1.1    |Bagheri                                     |
|-----------------+--------------------------------------------|
|AVALANCHE: v1    |Basel Alomair                               |
|corrections      |                                            |
|-----------------+--------------------------------------------|
|[S:Calico:S]: v8 |Christopher Taylor                          |
|withdrawn        |                                            |
|-----------------+--------------------------------------------|
|CBA: v1 v1-1     |Hossein Hosseini, Shahram Khazaei           |
|-----------------+--------------------------------------------|
|[S:CBEAM:S]: r1  |Markku-Juhani O. Saarinen                   |
|withdrawn        |                                            |
|-----------------+--------------------------------------------|
|Enchilada: v1    |Sandy Harris                                |
|v1.1             |                                            |
|-----------------+--------------------------------------------|
|[S:FASER:S]: v1  |Faith Chaza, Cameron McDonald, Roberto      |
|withdrawn        |Avanzi                                      |
|-----------------+--------------------------------------------|
|[S:HKC:S]: v1    |Matt Henricksen, Shinsaku Kiyomoto, Jiqiang |
|withdrawn        |Lu                                          |
|-----------------+--------------------------------------------|
|iFeed[AES]: v1   |Liting Zhang, Wenling Wu, Han Sui, Peng Wang|
|-----------------+--------------------------------------------|
|Julius: v1.0     |Lear Bahack                                 |
|addendum         |                                            |
|-----------------+--------------------------------------------|
|KIASU: v1        |J?r?my Jean, Ivica Nikoli?, Thomas Peyrin   |
|ordering addendum|                                            |
|-----------------+--------------------------------------------|
|LAC: v1          |Lei Zhang, Wenling Wu, Yanfeng Wang,        |
|                 |Shengbao Wu, Jian Zhang                     |
|-----------------+--------------------------------------------|
|[S:Marble:S]:    |                                            |
|v1.0 parameters  |Jian Guo                                    |
|withdrawn        |                                            |
|-----------------+--------------------------------------------|
|[S:McMambo:S]: v1|Watson Ladd                                 |
|withdrawn        |                                            |
|-----------------+--------------------------------------------|
|[S:PAES:S]: v1   |Dingfeng Ye, Peng Wang, Lei Hu, Liping Wang,|
|withdrawn        |Yonghong Xie, Siwei Sun, Ping Wang          |
|-----------------+--------------------------------------------|
|[S:PANDA:S]: v1  |Dingfeng Ye, Peng Wang, Lei Hu, Liping Wang,|
|withdrawn        |Yonghong Xie, Siwei Sun, Ping Wang          |
|-----------------+--------------------------------------------|
|POLAWIS: v1      |Arkadiusz Wysokinski, Ireneusz Sikora       |
|-----------------+--------------------------------------------|
|                 |Elif Bilge Kavun, Martin M. Lauridsen,      |
|Pr?st: v1 v1.1   |Gregor Leander, Christian Rechberger, Peter |
|                 |Schwabe, Tolga Yal??n                       |
|-----------------+--------------------------------------------|
|Raviyoyla: v1    |Rade Vuckovac                               |
|-----------------+--------------------------------------------|
|Sablier: v1      |Bin Zhang, Zhenqing Shi, Chao Xu, Yuan Yao, |
|                 |Zhenqi Li                                   |
|-----------------+--------------------------------------------|
|Silver: v1       |Daniel Penazzi, Miguel Montes               |
|-----------------+--------------------------------------------|
|Wheesht: v1      |Peter Maxwell                               |
|-----------------+--------------------------------------------|
|YAES: v1 v2      |Antoon Bosselaers, Fre Vercauteren          |
+--------------------------------------------------------------+
----------------------------------------------------------------
Version: This is version 2015.09.13 of the
caesar-submissions.html web page.
