package ec2

import (
	aws_logging "github.com/aws/smithy-go/logging"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "ec2")
)

type ec2Logger struct{}

func (l ec2Logger) Logf(classification aws_logging.Classification, format string, v ...interface{}) {
	switch classification {
	case aws_logging.Warn:
		log.Warnf(format, v)
	case aws_logging.Debug:
		log.Debugf(format, v)
	}
}
