rule ESET_Prikormka
{
	meta:
		description = "No description has been set in the source file - ESET"
		author = "ESET TI"
		id = "6073aa34-d385-5ae8-b97d-9b3d61015aae"
		date = "2016-05-10"
		modified = "2019-08-28"
		reference = "https://github.com/eset/malware-ioc/"
		source_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/groundbait/prikormka.yar#L130-L141"
		license_url = "https://github.com/eset/malware-ioc/blob/0f1104d8a7b3b77b66257d22588a281d8e93ca4b/LICENSE"
		logic_hash = "f64195e680fbaefedba248aa15b37ed30ba72f42958cc48963a140165e951bff"
		score = 75
		quality = 80
		tags = ""
		Author = "Anton Cherepanov"
		Description = "Operation Groundbait"
		Contact = "threatintel@eset.com"
		License = "BSD 2-Clause"

	condition:
		ESET_Prikormkadropper_PRIVATE or ESET_Prikormkamodule_PRIVATE or ESET_Prikormkaearlyversion_PRIVATE
}
