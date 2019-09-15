package db

import "fmt"

// CVEScore CVSS 3.0 score from NVD
type CVEScore struct {
	ID            string `gorm:"primary_key;index" json:"id"`
	ScoreSeverity string `json:"score_severity"`
	Vector        string `json:"vector"`

	Score               float64 `json:"score"`
	ImpactScore         float64 `json:"impact_score"`
	ExploitabilityScore float64 `json:"exploitability_score"`
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

// Get get cve score by id
func (score *CVEScore) Get(version string) error {
	handler := GetDBHandler(version)
	if handler == nil {
		return fmt.Errorf("Not found db hander for version '%s'", version)
	}

	return handler.Where("`id` = ?", score.ID).First(score).Error
}
