rule MALPEDIA_Win_Mpkbot_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "72738a74-041e-590e-bcbe-fef59ce6d7c8"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.mpkbot"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.mpkbot_auto.yar#L1-L118"
		license_url = "N/A"
		logic_hash = "84a9c41e42e448fecfbe039fb747c3f04c473f008e3e19f5ee4ba318bc990491"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 68???????? 50 ff15???????? a3???????? 8d45fc 50 683f000f00 }
		$sequence_1 = { a3???????? 8d45fc 50 683f000f00 6a00 }
		$sequence_2 = { 38450c 740a eb05 38450c 7503 }
		$sequence_3 = { 8d55f8 52 56 6a20 68???????? }
		$sequence_4 = { 55 8bec 56 57 6a00 ff15???????? 8bf0 }
		$sequence_5 = { 0fb630 8975d4 db45d4 d84dc4 }
		$sequence_6 = { 8bf0 0fb7450c 50 0fb74508 50 56 }
		$sequence_7 = { 7507 38450c 740a eb05 }
		$sequence_8 = { ff15???????? ff7508 a3???????? ffd0 5d c3 55 }
		$sequence_9 = { ff15???????? ffd6 50 ffd7 }

	condition:
		7 of them and filesize <139264
}
