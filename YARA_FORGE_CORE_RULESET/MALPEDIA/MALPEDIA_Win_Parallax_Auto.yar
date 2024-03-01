rule MALPEDIA_Win_Parallax_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "3331f8f9-ca97-5323-a8b7-4a2a5bd3b734"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.parallax"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.parallax_auto.yar#L1-L123"
		license_url = "N/A"
		logic_hash = "2375ab4fbfb357ff0388c05531234fe1711b2c1ab93377989bbf9dcbb0552a8e"
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
		$sequence_0 = { 8dbf8c000000 b934000000 f3a4 5e 56 ff7508 }
		$sequence_1 = { ff7508 ff9698010000 5e 5d c21400 55 8bec }
		$sequence_2 = { 8b5234 83c234 8915???????? 83be1801000000 7545 83be1801000000 7401 }
		$sequence_3 = { ff763c 683c800000 ff35???????? ff92e0010000 6a00 }
		$sequence_4 = { 7411 8b75ec 8b7de0 8b4de8 f3a4 }
		$sequence_5 = { 85c0 7418 8bf8 8b35???????? b8ffffffff f0874704 50 }
		$sequence_6 = { 6a00 ff9628010000 6a04 68???????? }
		$sequence_7 = { e9???????? 3d34800000 750d ff7514 ff7510 e8???????? eb6d }
		$sequence_8 = { 8b5634 83c234 52 52 }
		$sequence_9 = { 83e934 8b4734 83c034 8b15???????? 50 51 ff92dc000000 }

	condition:
		7 of them and filesize <352256
}
