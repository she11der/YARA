rule EMBEERESEARCH_Win_Redline_Updated_Bytecodes_Oct_2023
{
	meta:
		description = "Configuration related bytecodes in redline .net files"
		author = "Matthew @ Embee_Research"
		id = "1e4470cf-fad3-57e5-8a95-deb97e98dbdc"
		date = "2023-10-11"
		modified = "2023-10-11"
		reference = "https://github.com/embee-research/Yara-detection-rules/"
		source_url = "https://github.com/embee-research/Yara-detection-rules//blob/d4226e586a49cd4d1eede9a58738509689cf059f/Rules/win_redline_bytecodes_oct_2023.yar#L2-L35"
		license_url = "N/A"
		hash = "0cc3a0f8b48ef8d8562b9cdf9c7cfe7f63faf43a5ac6dc6973dc8bf13b6c88cf"
		logic_hash = "77273ba3736baf2c197fb8b17de1e22ba8f2380f73f9114f324ef56bfa508654"
		score = 75
		quality = 75
		tags = ""

	strings:
		$s_1 = {   
				20 ?? ?? ?? ?? 											// ldc.i4
				2B 00       											// br.s
				28 ?? ?? ?? 2B 											// Call
				80 ?? ?? ?? 04 											// stsfld
				(20 ?? ?? ?? ?? 2B00 28 ?? ?? ?? 2B | 72 ?? ?? ?? 70)   // ldc.i4, br.s, call OR ldstr
				80 ?? ?? ?? 04      									// Call
				(20 ?? ?? ?? ?? 2B00 28 ?? ?? ?? 2B | 72 ?? ?? ?? 70)   // ldc.i4, br.s, call OR ldstr
				80 ?? ?? ?? 04 											// Call		
				20 ?? ?? ?? ?? 											// ldc.i4
				2B00            										// br.s
				28 ?? ?? ?? 2B      									// Call
				80 ?? ?? ?? 04 											// stsfld
				2A 														// ret
			}
		$s_2 = "mscoree.dll"

	condition:
		$s_1 and $s_2
}
