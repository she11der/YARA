rule ESET_Keydnap_Backdoor_Packer
{
	meta:
		description = "OSX/Keydnap packed backdoor"
		author = "Marc-Etienne M.Léveillé"
		id = "f29ad5af-bc86-5764-9451-5a8363788c4e"
		date = "2016-07-06"
		modified = "2016-07-06"
		reference = "http://www.welivesecurity.com/2016/07/06/new-osxkeydnap-malware-is-hungry-for-credentials"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/keydnap/keydnap.yar#L51-L67"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "b1740bf38376be81d3b42306c2ce81f578c0b5c9db804f063836bf98f57ed147"
		score = 75
		quality = 80
		tags = ""
		version = "1"

	strings:
		$upx_string = "This file is packed with the UPX"
		$packer_magic = "ASS7"
		$upx_magic = "UPX!"

	condition:
		$upx_string and $packer_magic and not $upx_magic
}
