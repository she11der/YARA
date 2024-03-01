import "pe"

rule SIGNATURE_BASE_MAL_EXE_Lockbit_V2 : FILE
{
	meta:
		description = "Detection for LockBit version 2.x from 2011"
		author = "Silas Cutler, modified by Florian Roth"
		id = "a2c27110-e63b-5f93-88a0-98c12811e8b4"
		date = "2023-01-01"
		modified = "2023-01-06"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_100days_of_yara_2023.yar#L144-L169"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "00260c390ffab5734208a7199df0e4229a76261c3f5b7264c4515acb8eb9c2f8"
		logic_hash = "9472727d75e34d8bf87c56b74a6dfc04052e621b5fe31732ea9a10c76a05e0c0"
		score = 80
		quality = 60
		tags = "FILE"
		version = "1.0"
		DaysofYARA = "1/100"

	strings:
		$s_ransom_note01 = "that is located in every encrypted folder." wide
		$s_ransom_note02 = "Would you like to earn millions of dollars?" wide
		$x_ransom_tox = "3085B89A0C515D2FB124D645906F5D3DA5CB97CEBEA975959AE4F95302A04E1D709C3C4AE9B7" wide
		$x_ransom_url = "http://lockbitapt6vx57t3eeqjofwgcglmutr3a35nygvokja5uuccip4ykyd.onion" wide
		$s_str1 = "Active:[ %d [                  Completed:[ %d" wide
		$x_str2 = "\\LockBit_Ransomware.hta" wide ascii
		$s_str2 = "Ransomware.hta" wide ascii

	condition:
		uint16(0)==0x5A4D and (1 of ($x*) or 2 of them ) or 3 of them
}
