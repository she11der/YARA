import "pe"

rule SIGNATURE_BASE_SUSP_ELF_Invalid_Version : FILE
{
	meta:
		description = "Identify ELF file that has mangled header info."
		author = "@shellcromancer"
		id = "5bd97fdd-0912-5f9b-877c-91fff9b98dea"
		date = "2023-01-01"
		modified = "2023-12-05"
		reference = "https://tmpout.sh/1/1.html"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_100days_of_yara_2023.yar#L70-L86"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "05379bbf3f46e05d385bbd853d33a13e7e5d7d50"
		logic_hash = "33f096318647867bcd90d7ba77878f43d34477b2b2cbd7410c191e60573d6cd5"
		score = 55
		quality = 85
		tags = "FILE"
		version = "0.1"

	condition:
		( uint32(0)==0x464c457f and uint8(0x6)>1)
}
