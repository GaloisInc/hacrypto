INFORMAL_BON_FILES = HACrypto.bon \
                     CoreInformal.bon \
                     CiphersInformal.bon \
                     HashesInformal.bon \
                     KeysInformal.bon \
                     MACInformal.bon \
                     SignaturesInformal.bon \
                     TextInformal.bon \
                     ThreatsInformal.bon
FORMAL_BON_FILES = Hashes.bon 
REQUIREMENTS = Creation.bon \
               Events.bon \
               Scenarios.bon
BON_FILES = $(INFORMAL_BON_FILES) $(FORMAL_BON_FILES) $(REQUIREMENTS)

.PHONY: all java

all: hacrypto-iig.dot index.txt index.html html/index.html java

java:
	javac hacrypto/*.java

hacrypto-icg.dot: $(BON_FILES)
	bonc -g ICG $(BON_FILES) > hacrypto-icg.dot

hacrypto-iig.dot: $(BON_FILES)
	bonc -p IIG -po hacrypto-iig.dot $(BON_FILES)

index.txt: $(BON_FILES)
	bonc -po index.txt -p TXT $(BON_FILES)

index.html: $(BON_FILES)
	bonc -po index.html -p HTML $(BON_FILES)

html/index.html: $(BON_FILES)
	bonc -p NEWHTML -po html $(BON_FILES)
