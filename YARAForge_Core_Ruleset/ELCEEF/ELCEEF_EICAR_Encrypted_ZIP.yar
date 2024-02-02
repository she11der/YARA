rule ELCEEF_EICAR_Encrypted_ZIP
{
	meta:
		description = "Detects EICAR file in any encrypted ZIP archive"
		author = "marcin@ulikowski.pl"
		id = "c12d42de-356a-584b-9c48-71e65940f1cf"
		date = "2022-12-13"
		modified = "2022-12-16"
		reference = "https://github.com/elceef/yara-rulz"
		source_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/rules/EICAR_Encrypted_ZIP.yara#L14-L44"
		license_url = "https://github.com/elceef/yara-rulz/blob/0bb432b9e4157448c5c7e07b01409495605689d5/LICENSE"
		logic_hash = "56851056671bde38338bd200d9fde59c042f35a2cd84ac9401e716f376c9502c"
		score = 75
		quality = 75
		tags = ""

	strings:
		$local = {
			50 4b 03 04 // local file header signature (PK)
			?? 00 // minimum version
			?? 00 // flags (bit 0 and 6 indicate encryption)
			?? 00 // compression method
			?? ?? // last modification time
			?? ?? // last modification date
			?? ?? ?? ?? // CRC-32 of uncompressed and unencrypted data
			?? ?? ?? ?? // compressed size
			?? ?? ?? ?? // uncompressed size
}