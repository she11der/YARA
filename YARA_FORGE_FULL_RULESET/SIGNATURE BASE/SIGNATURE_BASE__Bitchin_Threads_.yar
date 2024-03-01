import "pe"

rule SIGNATURE_BASE__Bitchin_Threads_
{
	meta:
		description = "Auto-generated rule on file =Bitchin Threads=.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		id = "3a51e76c-b360-5f10-961c-ecc3ea3fa3c9"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L334-L345"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "7491b138c1ee5a0d9d141fbfd1f0071b"
		logic_hash = "f43fec37d9dc668b562838465e5696e502c638b207e7af6a77fac5a8b00e92a8"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s0 = "DarKPaiN"
		$s1 = "=BITCHIN THREADS"

	condition:
		all of them
}
