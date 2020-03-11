package db

import "fmt"

// CVEScore CVSS 3.0 score from NVD
type CVEScore struct {
	ID            string `gorm:"primary_key;index" json:"id"`
	ScoreSeverity string `json:"score_severity"`
	CVSS          string `json:"cvss"`
	Score               float64 `json:"score"`
}

// CVEScoreList cve score list
type CVEScoreList []*CVEScore

// Create insert cve score list
func (list CVEScoreList) Create(version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}

	var tx = handler.Begin()
	for _, score := range list {
		var info CVEScore
		tx.Where("`id` = ?", score.ID).First(&info)
		if info.ID == score.ID {
			// exists
			continue
		}

		err := tx.Create(score).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

func (list CVEScoreList) UpdateCVE(version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}

	var tx = handler.Begin()
	for _, score := range list {
		var info CVE
		tx.Where("`id` = ?", score.ID).First(&info)
		if info.Score == score.Score {
			// exists
			continue
		}

		err := tx.Model(&CVE{}).Where("`id` = ?", score.ID).Updates(map[string]interface{}{
			"cvss":  score.CVSS,
			"score": score.Score,
		}).Error
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit().Error
}

// Get get cve score by id
func (score *CVEScore) Get(version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}

	return handler.Where("`id` = ?", score.ID).First(score).Error
}
