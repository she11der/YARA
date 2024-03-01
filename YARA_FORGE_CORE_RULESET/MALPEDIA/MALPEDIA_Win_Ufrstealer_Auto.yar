rule MALPEDIA_Win_Ufrstealer_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "87df7a80-59b4-5e49-9e5c-787423bd5a1a"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.ufrstealer"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.ufrstealer_auto.yar#L1-L129"
		license_url = "N/A"
		logic_hash = "bbd8353728980ed7d41eeaaf6b45527dc201d1c8bc1c51c590cb1fee36b76ae8"
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
		$sequence_0 = { 6a01 6a00 6a00 68???????? 6a00 68???????? ff15???????? }
		$sequence_1 = { 0bc0 7529 8b43fc 03d8 8b03 83c304 83f8ff }
		$sequence_2 = { ffb5ecf3ffff ff15???????? 5b 5f 5e c9 }
		$sequence_3 = { 894df4 8b75f4 83ee01 c745f008000000 0fb64eff 0fb616 83f97f }
		$sequence_4 = { 03c1 80383a 7505 c60000 eb03 49 }
		$sequence_5 = { ff35???????? ff15???????? 85c0 0f842debffff a3???????? 68???????? ff15???????? }
		$sequence_6 = { 0f85c0000000 0fb60d???????? a1???????? 8808 8305????????01 894dfc bb???????? }
		$sequence_7 = { 8d45dc 6a04 50 e8???????? 8305????????04 e8???????? }
		$sequence_8 = { 50 68???????? 68???????? 6a00 ff15???????? 68???????? ff15???????? }
		$sequence_9 = { c745d80e000000 33c0 8b75d8 8bc8 8db65c884200 }

	condition:
		7 of them and filesize <770048
}
