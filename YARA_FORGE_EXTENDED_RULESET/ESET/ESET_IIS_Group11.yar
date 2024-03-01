import "pe"

rule ESET_IIS_Group11
{
	meta:
		description = "Detects Group 11 native IIS malware family"
		author = "ESET Research"
		id = "e9dac67a-1675-5198-ad26-d555696844f9"
		date = "2021-08-04"
		modified = "2021-08-04"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/badiis/badiis.yar#L425-L455"
		license_url = "https://github.com/eset/malware-ioc/blob/16bfa66e417b8db8ab63b928388417afd0d981db/LICENSE"
		logic_hash = "a67b6b49b5fc2c7f260c06201c59478f5472de63091c510af82d526c410abb0c"
		score = 75
		quality = 80
		tags = ""
		license = "BSD 2-Clause"
		version = "1"

	strings:
		$s1 = "DnsQuery_A"
		$s2 = "&reurl="
		$s3 = "&jump=1"
		$s4 = "JVVRaeof"
		$s5 = "ncpmg::0"
		$s6 = "zkpzz0cnnuqwnw0eqo"
		$s7 = "jvvr<11yyy0cnnuqwnw0eqo130rjrAeofqwv?"

	condition:
		ESET_IIS_Native_Module_PRIVATE and 3 of ($s*)
}
