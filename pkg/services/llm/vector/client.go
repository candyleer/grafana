package vector

import (
	"context"

	qdrant "github.com/qdrant/go-client/qdrant"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

type VectorClient interface {
	Collections(ctx context.Context) ([]string, error)
	CollectionExists(ctx context.Context, collection string) (bool, error)
	CreateCollection(ctx context.Context, collection string, size uint64) error
	PointExists(ctx context.Context, collection string, id uint64) (bool, error)
	UpsertColumnar(ctx context.Context, collection string, ids []uint64, embeddings [][]float32, payloadJSONs []string) error
	Search(ctx context.Context, collection string, vector []float32, limit uint64) ([]string, error)
}

type qdrantClient struct {
	conn              *grpc.ClientConn
	collectionsClient qdrant.CollectionsClient
	pointsClient      qdrant.PointsClient
}

func NewQdrantClient(addr string) (VectorClient, func(), error) {
	conn, err := grpc.DialContext(context.Background(), addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, err
	}
	cancel := func() {
		defer conn.Close()
	}
	return &qdrantClient{
		conn:              conn,
		collectionsClient: qdrant.NewCollectionsClient(conn),
		pointsClient:      qdrant.NewPointsClient(conn),
	}, cancel, nil
}

func (q *qdrantClient) Collections(ctx context.Context) ([]string, error) {
	collections, err := q.collectionsClient.List(ctx, &qdrant.ListCollectionsRequest{})
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(collections.Collections))
	for _, c := range collections.Collections {
		names = append(names, c.Name)
	}
	return names, nil
}

func (q *qdrantClient) CollectionExists(ctx context.Context, collection string) (bool, error) {
	_, err := q.collectionsClient.Get(ctx, &qdrant.GetCollectionInfoRequest{
		CollectionName: collection,
	}, grpc.WaitForReady(true))
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			return false, err
			// Error was not a status error
		}
		if st.Code() == codes.NotFound {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (q *qdrantClient) CreateCollection(ctx context.Context, collection string, size uint64) error {
	_, err := q.collectionsClient.Create(ctx, &qdrant.CreateCollection{
		CollectionName: collection,
		VectorsConfig: &qdrant.VectorsConfig{
			Config: &qdrant.VectorsConfig_Params{
				Params: &qdrant.VectorParams{
					Size: size,
					// TODO: make this customizable
					Distance: qdrant.Distance_Cosine,
				},
			},
		},
	})
	return err
}

func (q *qdrantClient) PointExists(ctx context.Context, collection string, id uint64) (bool, error) {
	point, err := q.pointsClient.Get(ctx, &qdrant.GetPoints{
		CollectionName: collection,
		Ids: []*qdrant.PointId{
			{PointIdOptions: &qdrant.PointId_Num{Num: id}},
		},
	}, grpc.WaitForReady(true))
	if err != nil {
		st, ok := status.FromError(err)
		if !ok {
			return false, err
			// Error was not a status error
		}
		if st.Code() == codes.NotFound {
			return false, nil
		}
		return false, err
	}
	if point.Result == nil {
		return false, nil
	}
	return true, nil
}

func (q *qdrantClient) UpsertColumnar(ctx context.Context, collection string, ids []uint64, embeddings [][]float32, payloadJSONs []string) error {
	waitUpsert := false
	upsertPoints := make([]*qdrant.PointStruct, 0, len(ids))
	for i, id := range ids {
		point := &qdrant.PointStruct{
			Id: &qdrant.PointId{
				PointIdOptions: &qdrant.PointId_Num{Num: id},
			},
			Vectors: &qdrant.Vectors{VectorsOptions: &qdrant.Vectors_Vector{Vector: &qdrant.Vector{Data: embeddings[i]}}},
			Payload: map[string]*qdrant.Value{
				"metadata": {
					Kind: &qdrant.Value_StringValue{StringValue: payloadJSONs[i]},
				},
			},
		}
		upsertPoints = append(upsertPoints, point)
	}
	_, err := q.pointsClient.Upsert(ctx, &qdrant.UpsertPoints{
		CollectionName: collection,
		Points:         upsertPoints,
		Wait:           &waitUpsert,
	}, grpc.WaitForReady(true))
	return err
}

func (q *qdrantClient) Search(ctx context.Context, collection string, vector []float32, limit uint64) ([]string, error) {
	result, err := q.pointsClient.Search(ctx, &qdrant.SearchPoints{
		CollectionName: collection,
		Vector:         vector,
		Limit:          limit,
		// Include all payloads in the search result
		WithVectors: &qdrant.WithVectorsSelector{SelectorOptions: &qdrant.WithVectorsSelector_Enable{Enable: false}},
		WithPayload: &qdrant.WithPayloadSelector{SelectorOptions: &qdrant.WithPayloadSelector_Enable{Enable: true}},
	})
	if err != nil {
		return nil, err
	}
	payloads := make([]string, 0, len(result.GetResult()))
	for _, v := range result.GetResult() {
		payload := v.Payload["metadata"]
		// TODO: handle non-strings, in case they get there
		payloads = append(payloads, payload.GetStringValue())
	}
	return payloads, nil
}
