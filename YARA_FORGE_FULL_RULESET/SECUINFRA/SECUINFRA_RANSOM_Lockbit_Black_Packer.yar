import "pe"
import "console"
import "math"

rule SECUINFRA_RANSOM_Lockbit_Black_Packer : Ransomware FILE
{
	meta:
		description = "Detects the packer used by Lockbit Black (Version 3)"
		author = "SECUINFRA Falcon Team"
		id = "f4c1a12b-eb89-5a46-97a9-f0207ca1bbde"
		date = "2022-07-04"
		modified = "2022-07-04"
		reference = "https://twitter.com/vxunderground/status/1543661557883740161"
		source_url = "https://github.com/SIFalcon/Detection/blob/2d7c66d7d16c7541bf2a9a83a7a6d334364a26fd/Yara/Malware/RANSOM_Lockbit_Black_Packer.yar#L5-L40"
		license_url = "N/A"
		logic_hash = "cde7f5374b97b2462cfd951994b6bb3ef0962e1be71253e25ca14d53c3d3d615"
		score = 75
		quality = 45
		tags = "FILE"
		tlp = "WHITE"
		hash0 = "80e8defa5377018b093b5b90de0f2957f7062144c83a09a56bba1fe4eda932ce"
		hash1 = "506f3b12853375a1fbbf85c82ddf13341cf941c5acd4a39a51d6addf145a7a51"
		hash2 = "d61af007f6c792b8fb6c677143b7d0e2533394e28c50737588e40da475c040ee"

	strings:
		$sectionname0 = ".rdata$zzzdbg" ascii
		$sectionname1 = ".xyz" ascii fullword
		$check0 = {3d 75 80 91 76 ?? ?? 3d 1b a4 04 00 ?? ?? 3d 9b b4 84 0b}
		$check1 = {3d 75 ba 0e 64}
		$asciiCalc = {66 83 f8 41 ?? ?? 66 83 f8 46 ?? ?? 66 83 e8 37}

	condition:
		uint16(0)==0x5a4d and filesize >111KB and filesize <270KB and all of ($sectionname*) and any of ($check*) and $asciiCalc and for any i in (0..pe.number_of_sections-1) : (math.entropy(pe.sections[i].raw_data_offset,pe.sections[i].raw_data_size)>7.9 and (pe.sections[i].name==".text" or pe.sections[i].name==".data" or pe.sections[i].name==".pdata") and console.log("High Entropy section found:",pe.sections[i].name))
}
