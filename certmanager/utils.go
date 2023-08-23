package certmanager

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
)

type (
	addFunc             = addFuncT[interface{}]
	updateFunc          = updateFuncT[interface{}]
	deleteFunc          = deleteFuncT[interface{}]
	addFuncT[T any]     func(T)
	updateFuncT[T any]  func(T, T)
	deleteFuncT[T any]  func(T)
	keyFunc             = keyFuncT[interface{}, interface{}]
	keyFuncT[T, U any]  func(T) (U, error)
	EnqueueFunc         = EnqueueFuncT[interface{}]
	EnqueueFuncT[T any] func(T) error
)

func retryFunc(ctx context.Context, retryInterval, timeout time.Duration, logger logr.Logger, msg string, run func(context.Context) error) func() error {
	return func() error {
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		registerTicker := time.NewTicker(retryInterval)
		defer registerTicker.Stop()
		var err error
		for {
			select {
			case <-registerTicker.C:
				if err = run(ctx); err != nil {
					logger.V(2).Info(msg, "reason", err.Error())
				} else {
					return nil
				}
			case <-ctx.Done():
				return fmt.Errorf("retry times out: %w", err)
			}
		}
	}
}

func AddEventHandlers(informer cache.SharedInformer, a addFunc, u updateFunc, d deleteFunc) {
	_, _ = informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    a,
		UpdateFunc: u,
		DeleteFunc: func(obj interface{}) {
			d(GetObjectWithTombstone(obj))
		},
	})
}

func AddDefaultEventHandlers(logger logr.Logger, informer cache.SharedInformer, queue workqueue.RateLimitingInterface) EnqueueFunc {
	return AddKeyedEventHandlers(logger, informer, queue, MetaNamespaceKey)
}

func AddKeyedEventHandlers(logger logr.Logger, informer cache.SharedInformer, queue workqueue.RateLimitingInterface, parseKey keyFunc) EnqueueFunc {
	enqueueFunc := LogError(logger, Parse(parseKey, Queue(queue)))
	AddEventHandlers(informer, AddFunc(logger, enqueueFunc), UpdateFunc(logger, enqueueFunc), DeleteFunc(logger, enqueueFunc))
	return enqueueFunc
}

func LogError[K any](logger logr.Logger, inner EnqueueFuncT[K]) EnqueueFuncT[K] {
	return func(obj K) error {
		err := inner(obj)
		if err != nil {
			logger.V(2).Error(err, "failed to compute key name", "obj", obj)
		}
		return err
	}
}

func Queue(queue workqueue.RateLimitingInterface) EnqueueFunc {
	return func(obj interface{}) error {
		queue.Add(obj)
		return nil
	}
}

func MetaNamespaceKey(obj interface{}) (interface{}, error) {
	return cache.MetaNamespaceKeyFunc(obj)
}

func AddFunc(logger logr.Logger, enqueue EnqueueFunc) addFunc {
	return func(obj interface{}) {
		if err := enqueue(obj); err != nil {
			logger.V(2).Error(err, "failed to enqueue object", "obj", obj)
		}
	}
}

func UpdateFunc(logger logr.Logger, enqueue EnqueueFunc) updateFunc {
	return func(old, obj interface{}) {
		oldMeta := old.(metav1.Object)
		objMeta := obj.(metav1.Object)
		if oldMeta.GetResourceVersion() != objMeta.GetResourceVersion() {
			if err := enqueue(obj); err != nil {
				logger.V(2).Error(err, "failed to enqueue object", "obj", obj)
			}
		}
	}
}

func DeleteFunc(logger logr.Logger, enqueue EnqueueFunc) deleteFunc {
	return func(obj interface{}) {
		if err := enqueue(obj); err != nil {
			logger.V(2).Error(err, "failed to enqueue object", "obj", obj)
		}
	}
}

func GetObjectWithTombstone(obj interface{}) interface{} {
	tombstone, ok := obj.(cache.DeletedFinalStateUnknown)
	if ok {
		return tombstone.Obj
	}
	return obj
}

func Parse[K, L any](parseKey keyFuncT[K, L], inner EnqueueFuncT[L]) EnqueueFuncT[K] {
	return func(obj K) error {
		if key, err := parseKey(obj); err != nil {
			return err
		} else {
			return inner(key)
		}
	}
}
