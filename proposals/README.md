1. Development of method for quantitative measurement of full cipher
   subsystem(s) performance and energy, including, in increasing
   concentric circles of architecture from center to outside, cipher
   implementation, typical network protocol, network stack, radio, and
   PCB.

2. Development of ultra-high performance formally verified ASICs.

3. Development of ultra-high performance and ultra-low slice count
   formally verified FPGAs.

4. Development of formally verified side-channel-free synthesized
   software and hardware algorithm implementations.

5. Development of a full “packaged” verified software solution
   integrated into existing or new crypto libraries.

6. Completing the software and hardware architectural synthesis
   pipeline to demonstrate automatic co-design synthesis of
   high-performance, formally verifiable ciphers and their entire
   surrounding library/framework.
   
3a/6. The FPGA target you mentioned below is becoming more prevalent
   in our space applications. We might consider incorporating more of
   the crypto-subsystem (beyond algorithm) with a specific small
   satellite target. In many cases this is a mix of software and
   hardware - either FPGA fabric coupled with ARM processor on die, or
   full ASIC.

4. Definitely have an interest here.

   (Jason 140, Nathan 200, Brian 300, Adam F. 160)

5a. With an IoT focus, many of our folks are looking at software
   solutions for multiple platforms (ourselves included). Considering
   multiple software platforms (e.g., MSP430, AVR, ARM, etc.) to
   produce a verified software solution seems like a huge asset
   here. As in 3a, we'd like to incorporate more of the
   crypto-subsystem as well. It might be an interesting demonstration
   that we could put together to target a microcontroller platform,
   possibly SCADA hardware, etc.

   (Jamey 100, Pat 150, Dan Z. 80+)

- Later

   Tristan 140, Getty 140 (Nov/Dec)
