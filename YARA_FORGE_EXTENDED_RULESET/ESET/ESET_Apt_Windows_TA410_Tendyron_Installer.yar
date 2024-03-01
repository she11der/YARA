import "pe"

rule ESET_Apt_Windows_TA410_Tendyron_Installer
{
	meta:
		description = "TA410 Tendyron Installer"
		author = "ESET Research"
		id = "95ccad1c-99fb-5d38-aec0-650db3e06b35"
		date = "2020-12-09"
		modified = "2022-04-27"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/ta410/ta410.yar#L55-L73"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "9c3afb924747614f27c31cf2c3d98f4932a9d11597a3ac94263bf93be02801da"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "Tendyron" wide
		$s2 = "OnKeyToken_KEB.dll" wide
		$s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide
		$s4 = "Global\\8D32CCB321B2"
		$s5 = "\\RTFExploit\\"

	condition:
		int16 (0)==0x5A4D and 3 of them
}
