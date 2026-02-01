package jobs

import (
	"context"
	"log"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	academicsv1 "semaphore/academics/academics/v1"
	"semaphore/attendance/internal/config"
)

func StartSignatureCloseJob(ctx context.Context, cfg config.Config, academics academicsv1.AcademicsCommandServiceClient) {
	if !cfg.SignatureCloseJobEnabled {
		return
	}
	if academics == nil {
		log.Printf("signature close job disabled: academics client not configured")
		return
	}
	interval := cfg.SignatureCloseJobInterval
	if interval <= 0 {
		interval = time.Minute
	}
	timeout := cfg.SignatureCloseJobTimeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				now := time.Now().UTC()
				tickCtx, cancel := context.WithTimeout(ctx, timeout)
				resp, err := academics.CloseExpiredCourses(tickCtx, &academicsv1.CloseExpiredCoursesRequest{
					Now: timestamppb.New(now),
				})
				cancel()
				if err != nil {
					log.Printf("signature close job error: %v", err)
					continue
				}
				if resp.GetClosedCount() > 0 {
					log.Printf("signature close job closed %d courses", resp.GetClosedCount())
				}
			}
		}
	}()
}
