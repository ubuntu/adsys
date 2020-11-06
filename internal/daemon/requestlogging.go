package daemon

import (
	"context"

	log "github.com/ubuntu/adsys/internal/grpc/logstreamer"
	"google.golang.org/grpc"
)

// OnNewConnection uses the idler for timeout and log request starting information
func (d *Daemon) OnNewConnection(ctx context.Context, info *grpc.StreamServerInfo) {
	d.idler.OnNewConnection(ctx, info)
	if info != nil {
		log.Debugf(ctx, "New request %s", info.FullMethod)
	}
}

// OnDoneConnection resets the idler for timeout and log request ending information
func (d *Daemon) OnDoneConnection(ctx context.Context, info *grpc.StreamServerInfo) {
	if info != nil {
		log.Debugf(ctx, "Request %s done", info.FullMethod)
	}
	d.idler.OnDoneConnection(ctx, info)
}
