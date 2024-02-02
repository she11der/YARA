rule MALPEDIA_Win_Skinnyboy_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "c1dca40b-594e-536c-99f6-c4dd1e2fe372"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.skinnyboy"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.skinnyboy_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "70d89835d7c3795dc1cc1ad5fe812e10b23259f8f17b962d2f0a6c8239d19e5a"
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
		$sequence_0 = { 6a03 6a00 6a00 68bb010000 ffb5ccfeffff 56 ff15???????? }
		$sequence_1 = { ff30 8945f0 ff36 8975f4 }
		$sequence_2 = { 660fd68564feffff f30f7e05???????? 8d8576feffff 6a00 50 660fd6856cfeffff e8???????? }
		$sequence_3 = { ffd7 ffd3 6a00 6a00 }
		$sequence_4 = { c7856cffffff464b1153 c78570ffffff05170610 c78574ffffff035d591e c78578ffffff01591244 }
		$sequence_5 = { c1fb05 8bfe 83e71f c1e706 8b049d10110110 }
		$sequence_6 = { ff15???????? 8bf0 89b5d8feffff ffd3 }
		$sequence_7 = { c745bc79000000 660fd645c0 660fd645c8 c745e457000000 660fd645e8 660fd645f0 }
		$sequence_8 = { 85d2 740f 668b444de4 6631444dd0 41 3bca }
		$sequence_9 = { 8d45f4 50 ff7308 ff15???????? 8b15???????? 85c0 }

	condition:
		7 of them and filesize <176128
}