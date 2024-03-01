rule SIGNATURE_BASE_Dubseven_Dropper_Dialog_Remains : FILE
{
	meta:
		description = "Searches for related dialog remnants. How rude."
		author = "Matt Brooks, @cmatthewbrooks"
		id = "6029ea74-26fc-57d1-aaed-be1ea2138844"
		date = "2016-04-18"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/yara/apt_between-hk-and-burma.yar#L59-L80"
		license_url = "https://github.com/Neo23x0/signature-base/blob/995df52f47284d130b8cbf57d08c31e927e44c09/LICENSE"
		logic_hash = "322ddc1210b6bde393970c61113e6efcb87a3529db386323dfd08973e5d2703e"
		score = 75
		quality = 85
		tags = "FILE"

	strings:
		$dia1 = "fuckMessageBox 1.0" wide
		$dia2 = "Rundll 1.0" wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550 and any of them
}
