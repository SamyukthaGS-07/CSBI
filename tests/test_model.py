from csbi.model.predict import predict_risk


def test_predict_risk_shape():
    prediction = predict_risk({})
    assert 'scam_probability' in prediction
    assert 'risk' in prediction
