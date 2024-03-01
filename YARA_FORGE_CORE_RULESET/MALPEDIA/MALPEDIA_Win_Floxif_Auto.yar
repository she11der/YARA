rule MALPEDIA_Win_Floxif_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "dcbc6afb-5640-594e-8001-abd00982f671"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.floxif"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.floxif_auto.yar#L1-L126"
		license_url = "N/A"
		logic_hash = "0032adeaefefb80d7e1e935d3a462c453aec0c986c2f0bdf2924a1a8da50b164"
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
		$sequence_0 = { e8???????? 8945fc 837dfc02 7709 c745f401000000 eb09 8b45fc }
		$sequence_1 = { 3955f4 0f83c9000000 68???????? e8???????? }
		$sequence_2 = { 8b55fc c70200000000 8b45fc c7401000000000 8b45fc 8be5 }
		$sequence_3 = { c645e500 c645e6e1 c645e700 c645e87d c645e973 c645ea7a c645eb30 }
		$sequence_4 = { c645e500 c645e6bb c645e700 c645e828 c645e92b c645ea23 }
		$sequence_5 = { 7505 e9???????? 837dd800 7406 837dd805 7502 eb92 }
		$sequence_6 = { 83ec14 894df8 8b45f8 8b4808 }
		$sequence_7 = { ebaa 8d4d08 e8???????? 3945fc 7526 8d4d18 e8???????? }
		$sequence_8 = { 8b55fc 837a0400 7507 e8???????? eb11 8b4dfc e8???????? }
		$sequence_9 = { e8???????? e8???????? 83c410 eb44 83ec10 8bcc 8d5508 }

	condition:
		7 of them and filesize <352256
}