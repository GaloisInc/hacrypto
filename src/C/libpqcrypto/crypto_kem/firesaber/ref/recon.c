#include "apiorig.h"

#if Saber_type == 1
	#include "recon_LightSaber.inc"
#elif Saber_type == 2
	#include "recon_Saber.inc"
#elif Saber_type == 3
	#include "recon_FireSaber.inc"
#endif
