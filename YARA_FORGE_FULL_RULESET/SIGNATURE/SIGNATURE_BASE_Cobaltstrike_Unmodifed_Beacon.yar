rule SIGNATURE_BASE_Cobaltstrike_Unmodifed_Beacon
{
	meta:
		description = "Detects unmodified CobaltStrike beacon DLL"
		author = "yara@s3c.za.net"
		id = "8eeb03f9-9698-5a46-b45b-224d5c3f3df7"
		date = "2019-08-16"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/apt_cobaltstrike_evasive.yar#L309-L320"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		logic_hash = "10114a431fb70be8e18e67b22aa76bf2c0536f07d373f717c1dc51755e0847c9"
		score = 75
		quality = 85
		tags = ""

	strings:
		$loader_export = "ReflectiveLoader"
		$exportname = "beacon.dll"

	condition:
		all of them
}
