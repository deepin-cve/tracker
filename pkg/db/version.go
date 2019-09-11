package db

import (
	"sort"
)

// Version deepin and debian version
type Version struct {
	Version       string `gorm:"primary_key;index" json:"version"`
	DebianVersion string `json:"debian_version"`
	TrackerURL    string `json:"tracker_url"`
	ReleaseURL    string `json:"release_url"`

	DebianSeq int `json:"debian_seq"`
}

// VersionList version list
type VersionList []*Version

func (list VersionList) Len() int {
	return len(list)
}

func (list VersionList) Less(i, j int) bool {
	return list[i].DebianSeq > list[j].DebianSeq
}

func (list VersionList) Swap(i, j int) {
	list[i], list[j] = list[j], list[i]
}

// Create insert version
func (v *Version) Create() error {
	return CommonDB.Create(v).Error
}

// Get query by version
func (v *Version) Get() error {
	return CommonDB.Where("`version` = ?", v.Version).First(v).Error
}

// Update update
func (v *Version) Update() error {
	var tmp Version
	err := CommonDB.Where("`version` = ?", v.Version).First(&tmp).Error
	if err != nil {
		return err
	}
	if v.Equal(&tmp) {
		return nil
	}
	return CommonDB.Save(v).Error
}

// Equal compare
func (v *Version) Equal(target *Version) bool {
	return v.Version == target.Version &&
		v.DebianVersion == target.DebianVersion &&
		v.TrackerURL == target.TrackerURL &&
		v.ReleaseURL == target.ReleaseURL
}

// Delete delete version
func (v *Version) Delete() error {
	return CommonDB.Where("`version` = ?", v.Version).Delete(&Version{}).Error
}

// QueryVersionList return version list
func QueryVersionList() (VersionList, error) {
	var verList VersionList
	err := CommonDB.Find(&verList).Error
	if err != nil {
		return nil, err
	}

	sort.Sort(verList)
	return verList, nil
}
