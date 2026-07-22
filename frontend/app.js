const scanButton = document.getElementById('scan');
const urlInput = document.getElementById('url');
const scoreEl = document.getElementById('score');
const riskEl = document.getElementById('risk');
const clusterEl = document.getElementById('cluster');
const reasonsEl = document.getElementById('reasons');

scanButton.addEventListener('click', () => {
  const url = urlInput.value.trim();
  if (!url) {
    return;
  }
  scoreEl.textContent = '65';
  riskEl.textContent = 'medium';
  clusterEl.textContent = 'campaign-1';
  reasonsEl.innerHTML = '<li>Urgency language detected</li><li>Payment signals found</li><li>Weak trust markers</li>';
});
